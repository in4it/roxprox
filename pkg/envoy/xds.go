package envoy

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	xds "github.com/envoyproxy/go-control-plane/pkg/server"
	"github.com/google/go-cmp/cmp"
	pkgApi "github.com/in4it/roxprox/pkg/api"
	storage "github.com/in4it/roxprox/pkg/storage"
	n "github.com/in4it/roxprox/proto/notification"
	"github.com/juju/loggo"
	"google.golang.org/grpc"
)

var logger = loggo.GetLogger("xds")

type XDS struct {
	s           storage.Storage
	objects     []pkgApi.Object
	workQueue   *WorkQueue
	acmeContact string
}

func NewXDS(s storage.Storage, acmeContact, port string) *XDS {
	workQueue, err := NewWorkQueue(s, acmeContact)
	if err != nil {
		logger.Debugf("Couldn't initialize workqueue")
		panic(err)
	}
	x := &XDS{
		s:           s,
		workQueue:   workQueue,
		acmeContact: acmeContact,
	}

	server := xds.NewServer(x.workQueue.InitCache(), x.workQueue.InitCallback())
	if port != "" {
		grpcServer := grpc.NewServer()
		lis, _ := net.Listen("tcp", ":"+port)

		discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
		api.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
		api.RegisterClusterDiscoveryServiceServer(grpcServer, server)
		api.RegisterRouteDiscoveryServiceServer(grpcServer, server)
		api.RegisterListenerDiscoveryServiceServer(grpcServer, server)
		go func() {
			if err := grpcServer.Serve(lis); err != nil {
				panic(err)
				// error handling
			}
		}()
	}

	return x
}
func (x *XDS) WaitForFirstEnvoy() {
	x.workQueue.WaitForFirstEnvoy()
}
func (x *XDS) StartRenewalQueue() error {
	// run renewals
	renewals, err := NewRenewalQueue(x.s, x.acmeContact, x.workQueue)
	if err != nil {
		return err
	}
	renewals.StartQueue() // run queue once every hour for renewals

	err = renewals.CheckRenewals() // check immediately for renewals
	if err != nil {
		return err
	}
	return nil
}

func (x *XDS) ImportObjects() error {
	var (
		workQueueItems []WorkQueueItem
		err            error
		objects        []pkgApi.Object
	)
	objects, err = x.s.ListObjects()
	if err != nil {
		return err
	}
	// first read config objects
	for _, object := range objects {
		if object.Kind != "rule" {
			x.objects = append(x.objects, object)
			newitems, err := x.ImportObject(object)
			if err != nil {
				return err
			}
			workQueueItems = append(workQueueItems, newitems...)
		}
	}

	// read rules
	for _, object := range objects {
		if object.Kind == "rule" {
			rule := object.Data.(pkgApi.Rule)
			x.objects = append(x.objects, object)
			newitems, err := x.ImportRule(rule)
			if err != nil {
				return err
			}
			workQueueItems = append(workQueueItems, newitems...)
		}
	}

	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		return err
	}

	return nil
}

func (x *XDS) RemoveRule(rule pkgApi.Rule, ruleStillPresent bool) ([]WorkQueueItem, error) {
	// A s3 delete notification might happen after an add, so we're not removing the rule if there is an exact match
	var expectedRules int
	if ruleStillPresent {
		expectedRules = 1
	} else {
		expectedRules = 0
	}
	// check if matching is in use
	var workQueueItems []WorkQueueItem
	var conditionsToDelete int
	for _, condition := range rule.Spec.Conditions {
		if x.s.CountCachedObjectByCondition(condition) > expectedRules {
			// If there is only 1 match, then we're not going to remove the rule condition
			logger.Debugf("Not removing rule with conditions %s %s%s%s (is identical to other condition in other rule)", condition.Hostname, condition.Prefix, condition.Path, condition.Regex)
		} else {
			conditionsToDelete++

			action := x.getAction(rule.Metadata.Name, rule.Spec.Actions)
			newWorkQueueItem := WorkQueueItem{
				Action:         "deleteRoute",
				ListenerParams: x.getListenerParams(action, condition),
			}
			if rule.Spec.Certificate != "" {
				newWorkQueueItem.TLSParams = TLSParams{
					Name: rule.Metadata.Name,
				}
			}
			if rule.Spec.Auth.JwtProvider != "" {
				newWorkQueueItem.ListenerParams.Auth = Auth{
					JwtProvider: rule.Spec.Auth.JwtProvider,
				}
			}
			workQueueItems = append(workQueueItems, newWorkQueueItem)
		}
	}
	// delete cluster (has the same name as the rule)
	if conditionsToDelete == len(rule.Spec.Conditions) {
		workQueueItems = append(workQueueItems, WorkQueueItem{
			Action: "deleteCluster",
			ClusterParams: ClusterParams{
				Name: rule.Metadata.Name,
			},
		})
	}

	return workQueueItems, nil
}
func (x *XDS) ImportObject(object pkgApi.Object) ([]WorkQueueItem, error) {
	var workQueueItems []WorkQueueItem
	switch object.Kind {
	case "jwtProvider":
		jwtProvider := object.Data.(pkgApi.JwtProvider)
		logger.Debugf("Found jwtProvider with name %s and jwksUrl %s", jwtProvider.Metadata.Name, jwtProvider.Spec.RemoteJwks)
		u, err := url.Parse(jwtProvider.Spec.RemoteJwks)
		if err != nil {
			return workQueueItems, err
		}

		var port int64
		if u.Port() != "" {
			port, err = strconv.ParseInt(u.Port(), 10, 64)
			if err != nil {
				return workQueueItems, err
			}
		} else {
			if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		workQueueItems = append(workQueueItems, []WorkQueueItem{
			{
				Action: "createCluster",
				ClusterParams: ClusterParams{
					Name:           "jwtProvider_" + jwtProvider.Metadata.Name,
					TargetHostname: u.Hostname(),
					Port:           port,
				},
			},
			{
				Action: "updateListenerWithJwtProvider",
				ListenerParams: ListenerParams{
					Auth: x.getAuthParams(jwtProvider.Metadata.Name, jwtProvider),
				},
			},
		}...)
	}
	return workQueueItems, nil
}

func (x *XDS) getObject(kind, name string) (pkgApi.Object, error) {
	for _, v := range x.objects {
		if v.Kind == kind && v.Metadata.Name == name {
			return v, nil
		}
	}
	return pkgApi.Object{}, fmt.Errorf("object %s/%s not found", kind, name)
}

func (x *XDS) getRuleDeletionsWithinObject(cachedObject *pkgApi.Object, conditions []pkgApi.RuleConditions) []WorkQueueItem {
	var workQueueItems []WorkQueueItem
	cachedRule := cachedObject.Data.(pkgApi.Rule)
	cachedConditions := cachedRule.Spec.Conditions
	for _, cachedCondition := range cachedConditions {
		conditionFound := false
		conditionKey := -1
		for k, condition := range conditions {
			if cmp.Equal(condition, cachedCondition) {
				conditionFound = true
				conditionKey = k
			}
		}
		if conditionFound {
			logger.Debugf("Condition present (hostname: %s prefix: %s path: %s regex: %s methods: %s)",
				conditions[conditionKey].Hostname,
				conditions[conditionKey].Prefix,
				conditions[conditionKey].Path,
				conditions[conditionKey].Regex,
				strings.Join(conditions[conditionKey].Methods, ","))
		} else {
			logger.Debugf("Condition not present in new version, submitting removal of hostname: %s prefix: %s path: %s regex: %s methods: %s",
				cachedCondition.Hostname,
				cachedCondition.Prefix,
				cachedCondition.Path,
				cachedCondition.Regex,
				strings.Join(cachedCondition.Methods, ","))
			action := x.getAction(cachedRule.Metadata.Name, cachedRule.Spec.Actions)
			newWorkQueueItem := WorkQueueItem{
				Action:         "deleteRoute",
				ListenerParams: x.getListenerParams(action, cachedCondition),
			}
			if cachedRule.Spec.Certificate != "" {
				newWorkQueueItem.TLSParams = TLSParams{
					Name: cachedRule.Metadata.Name,
				}
			}
			if cachedRule.Spec.Auth.JwtProvider != "" {
				newWorkQueueItem.ListenerParams.Auth = Auth{
					JwtProvider: cachedRule.Spec.Auth.JwtProvider,
				}
			}
			workQueueItems = append(workQueueItems, newWorkQueueItem)
		}
	}

	return workQueueItems
}

func (x *XDS) getAction(ruleName string, actions []pkgApi.RuleActions) Action {
	var action Action
	for _, ruleAction := range actions {
		if ruleAction.Proxy.Hostname != "" {
			action.Type = "proxy"
			action.RuleName = ruleName
			action.Proxy.TargetHostname = ruleAction.Proxy.Hostname
			action.Proxy.Port = ruleAction.Proxy.Port
		}
	}
	return action
}
func (x *XDS) getListenerParams(action Action, condition pkgApi.RuleConditions) ListenerParams {
	return ListenerParams{
		Name:           action.RuleName,
		TargetHostname: action.Proxy.TargetHostname,
		Conditions: Conditions{
			Hostname: condition.Hostname,
			Prefix:   condition.Prefix,
			Path:     condition.Path,
			Regex:    condition.Regex,
			Methods:  condition.Methods,
		},
	}
}
func (x *XDS) getClusterParams(action Action) ClusterParams {
	return ClusterParams{
		Name:           action.RuleName,
		TargetHostname: action.Proxy.TargetHostname,
		Port:           action.Proxy.Port,
	}
}
func (x *XDS) getAuthParams(jwtProviderName string, jwtProvider pkgApi.JwtProvider) Auth {
	return Auth{
		JwtProvider: jwtProviderName,
		Issuer:      jwtProvider.Spec.Issuer,
		Forward:     jwtProvider.Spec.Forward,
		RemoteJwks:  jwtProvider.Spec.RemoteJwks,
	}
}

func (x *XDS) ImportRule(rule pkgApi.Rule) ([]WorkQueueItem, error) {
	var workQueueItems []WorkQueueItem
	action := x.getAction(rule.Metadata.Name, rule.Spec.Actions)
	if action.Type == "proxy" {
		// create cluster
		workQueueItem := WorkQueueItem{
			Action:        "createCluster",
			ClusterParams: x.getClusterParams(action),
		}
		workQueueItems = append(workQueueItems, workQueueItem)
		// create listener that proxies to targetHostname
		for _, condition := range rule.Spec.Conditions {
			// validation
			if rule.Spec.Certificate != "" && condition.Hostname == "" {
				return []WorkQueueItem{}, fmt.Errorf("Validation error: rule with certificate, but without a hostname condition - ignoring rule")

			}
			if condition.Hostname != "" || condition.Prefix != "" || condition.Path != "" || condition.Regex != "" {
				workQueueItem := WorkQueueItem{
					Action:         "createListener",
					ListenerParams: x.getListenerParams(action, condition),
				}
				// add auth info to parameter
				if rule.Spec.Auth.JwtProvider != "" {
					object, err := x.getObject("jwtProvider", rule.Spec.Auth.JwtProvider)
					workQueueItem.ListenerParams.Auth = x.getAuthParams(rule.Spec.Auth.JwtProvider, object.Data.(pkgApi.JwtProvider))
					if err != nil {
						logger.Infof("Could not set Auth parameters: %s - skipping for now", err)
					}
				}
				workQueueItems = append(workQueueItems, workQueueItem)

				if rule.Spec.Certificate == "letsencrypt" {
					// TLS listener
					certBundle, err := x.s.GetCertBundle(rule.Metadata.Name)
					if err != nil && err != x.s.GetError("errNotExist") {
						return workQueueItems, err
					}
					if err != nil && err == x.s.GetError("errNotExist") {
						// TODO: add to list for creation
						logger.Debugf("Certificate not found, needs to be created")
					}
					if err == nil {
						logger.Debugf("Certificate found, adding TLS")
						privateKeyPem, err := x.s.GetPrivateKeyPem(rule.Metadata.Name)
						if err != nil {
							return workQueueItems, err
						}
						workQueueItemTLS := workQueueItem
						workQueueItemTLS.Action = "createTLSListener"
						workQueueItemTLS.TLSParams = TLSParams{
							Name:       rule.Metadata.Name,
							CertBundle: certBundle,
							PrivateKey: privateKeyPem,
							Domain:     workQueueItem.ListenerParams.Conditions.Hostname,
						}
						workQueueItems = append(workQueueItems, workQueueItemTLS)
					}
				}
			}
		}
	}
	return workQueueItems, nil
}

func (x *XDS) CreateCertsForRules() error {
	var workQueueItems []WorkQueueItem
	// tls certs

	for _, object := range x.objects {
		if object.Kind == "rule" {
			rule := object.Data.(pkgApi.Rule)
			logger.Debugf("Looking for cert for %s (cert=%s)", rule.Metadata.Name, rule.Spec.Certificate)
			if rule.Spec.Certificate != "" {
				ruleConditionDomains := x.getRuleConditionDomains(rule.Spec.Conditions)
				cert, err := x.s.GetCertBundle(rule.Metadata.Name)

				if err != nil && err != x.s.GetError("errNotExist") {
					return err
				}
				if err != nil && err == x.s.GetError("errNotExist") {
					workQueueItems = append(workQueueItems, x.launchCreateCert(rule.Metadata.Name, ruleConditionDomains))
				} else {
					err := x.verifyCert(rule.Metadata.Name, cert, ruleConditionDomains)
					if err != nil {
						logger.Infof("Certificate not valid: %s", err)
						workQueueItems = append(workQueueItems, x.launchCreateCert(rule.Metadata.Name, ruleConditionDomains))
					} else {
						logger.Debugf("Verified domain for %s (cert=%s)", rule.Metadata.Name, rule.Spec.Certificate)
					}
				}
			}
		}
	}
	_, err := x.workQueue.Submit(workQueueItems)
	if err != nil {
		return err
	}
	return nil
}

func (x *XDS) verifyCert(name, certPEM string, domains []string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM for %s", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for (%s): %s", name, err.Error())
	}

	for _, domain := range domains {
		if err := cert.VerifyHostname(domain); err != nil {
			return fmt.Errorf("failed to verify hostname for certificate (%s): %s ", name, err.Error())
		}
	}
	return nil
}

func (x *XDS) getRuleConditionDomains(conditions []pkgApi.RuleConditions) []string {
	domains := []string{}
	for _, condition := range conditions {
		if condition.Hostname != "" {
			domains = append(domains, condition.Hostname)
		}
	}
	return domains
}

func (x *XDS) launchCreateCert(name string, domains []string) WorkQueueItem {
	// create cert
	logger.Debugf("Create certificate")
	workQueueItem := WorkQueueItem{
		Action: "verifyDomains",
		CreateCertParams: CreateCertParams{
			Name:    name,
			Domains: domains,
		},
	}
	return workQueueItem
}

func (x *XDS) StartObservingNotifications(queue chan []*n.NotificationRequest_NotificationItem) {
	go x.receiveFromQueue(queue)
}

func (x *XDS) receiveFromQueue(queue chan []*n.NotificationRequest_NotificationItem) {
	for {
		var (
			workQueueItems []WorkQueueItem
		)

		notifications := <-queue

		for _, v := range notifications {
			if v.EventName == "ObjectCreated:Put" {
				newItems, err := x.putObject(v.Filename)
				if err != nil {
					logger.Errorf("%s", err)
				} else {
					workQueueItems = append(workQueueItems, newItems...)
				}
			} else if v.EventName == "ObjectRemoved:Delete" {
				newItems, err := x.deleteObject(v.Filename)
				if err != nil {
					logger.Errorf("%s", err)
				} else {
					workQueueItems = append(workQueueItems, newItems...)
				}

			}
		}

		if len(workQueueItems) > 0 {
			_, err := x.workQueue.Submit(workQueueItems)
			if err != nil {
				logger.Errorf("ReceiveFromQueue Error while Submitting WorkQueue: %s", err)
			}

		}
	}
}

func (x *XDS) putObject(filename string) ([]WorkQueueItem, error) {
	var workQueueItems []WorkQueueItem

	// retrieve cached version
	cachedObjects, err := x.s.GetCachedObjectName(filename)
	if err != nil {
		logger.Infof("Couldn't find old object in cache (filename: %s)", filename)
	}

	objects, err := x.s.GetObject(filename)
	if err != nil {
		return workQueueItems, fmt.Errorf("Couldn't get new rule from storage: %s", err)
	}

	// compare new file with what's in cache, schedule cachedObjects that are not in the new object for deletion
	if cachedObjects != nil {
		workQueueItems = append(workQueueItems, x.getWorkingItemsForRemovedObjects(objects, cachedObjects)...)
	}

	// add new items
	for _, object := range objects {
		if object.Kind == "rule" {
			rule := object.Data.(pkgApi.Rule)
			// add new rules
			newItems, err := x.ImportRule(rule)
			if err != nil {
				return workQueueItems, fmt.Errorf("Couldn't import new rule: %s", err)
			}
			workQueueItems = append(workQueueItems, newItems...)
		}
		if object.Kind == "jwtProvider" {
			newItems, err := x.ImportObject(object)
			if err != nil {
				return workQueueItems, fmt.Errorf("Couldn't import new object: %s", err)
			}
			workQueueItems = append(workQueueItems, newItems...)
		}
	}
	return workQueueItems, nil
}
func (x *XDS) deleteObject(filename string) ([]WorkQueueItem, error) {
	objects, err := x.s.GetCachedObjectName(filename)
	if err != nil {
		return []WorkQueueItem{}, fmt.Errorf("Couldn't get new rule from storage cache: %s", err)
	}
	for _, object := range objects {
		if object.Kind == "rule" {
			rule := object.Data.(pkgApi.Rule)
			newItems, err := x.RemoveRule(rule, true /* rule still present? */)
			if err != nil {
				return []WorkQueueItem{}, fmt.Errorf("Couldn't remove rule: %s", err)
			}
			// delete cache entry
			x.s.DeleteCachedObject(filename)
			return newItems, nil
		}
	}
	return []WorkQueueItem{}, nil

}

func (x *XDS) getWorkingItemsForRemovedObjects(objects []pkgApi.Object, cachedObjects []*pkgApi.Object) []WorkQueueItem {

	// 1. check whether we need to remove full objects
	var workQueueItems []WorkQueueItem
	for _, cachedObject := range cachedObjects {
		objectFound := false
		for _, object := range objects {
			if object.Metadata.Name == cachedObject.Metadata.Name {
				objectFound = true
			}
		}
		if !objectFound {
			if cachedObject.Kind == "rule" {
				rule := cachedObject.Data.(pkgApi.Rule)
				newItems, err := x.RemoveRule(rule, false /* cache is already updated and rule is not present */)
				if err != nil {
					logger.Errorf("Couldn't remove rule: %s", err)
				} else {
					logger.Debugf("Adding work item to delete rule with name %s", cachedObject.Metadata.Name)
					workQueueItems = append(workQueueItems, newItems...)
				}
			}

		}
	}

	// 2. check whether we need to remove rules within objects
	for _, cachedObject := range cachedObjects {
		for _, object := range objects {
			if object.Metadata.Name == cachedObject.Metadata.Name {
				if object.Kind == "rule" {
					rule := object.Data.(pkgApi.Rule)
					workQueueItems = append(workQueueItems, x.getRuleDeletionsWithinObject(cachedObject, rule.Spec.Conditions)...)
				}
			}
		}
	}
	return workQueueItems
}
