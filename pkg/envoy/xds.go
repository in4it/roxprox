package envoy

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	xds "github.com/envoyproxy/go-control-plane/pkg/server"
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

func NewXDS(s storage.Storage, acmeContact string) *XDS {
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
	grpcServer := grpc.NewServer()
	lis, _ := net.Listen("tcp", ":8080")

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

func (x *XDS) RemoveRule(rule pkgApi.Rule) ([]WorkQueueItem, error) {
	// check if matching is in use
	var workQueueItems []WorkQueueItem
	for _, condition := range rule.Spec.Conditions {
		if x.s.CountCachedObjectByCondition(condition) > 1 {
			newWorkQueueItem := WorkQueueItem{
				Action: "deleteRoute",
				ListenerParams: ListenerParams{
					Name: rule.Metadata.Name,
					Conditions: Conditions{
						Hostname: condition.Hostname,
						Prefix:   condition.Prefix,
						Methods:  condition.Methods,
					},
				},
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
	workQueueItems = append(workQueueItems, WorkQueueItem{
		Action: "deleteCluster",
		ClusterParams: ClusterParams{
			Name: rule.Metadata.Name,
		},
	})

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
					Auth: Auth{
						JwtProvider: jwtProvider.Metadata.Name,
						Issuer:      jwtProvider.Spec.Issuer,
						Forward:     jwtProvider.Spec.Forward,
						RemoteJwks:  jwtProvider.Spec.RemoteJwks,
					},
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

func (x *XDS) ImportRule(rule pkgApi.Rule) ([]WorkQueueItem, error) {
	var workQueueItems []WorkQueueItem
	targetHostname := ""
	for _, action := range rule.Spec.Actions {
		if action.Proxy.Hostname != "" {
			targetHostname = action.Proxy.Hostname
			workQueueItem := WorkQueueItem{
				Action: "createCluster",
				ClusterParams: ClusterParams{
					Name:           rule.Metadata.Name,
					TargetHostname: targetHostname,
					Port:           action.Proxy.Port,
				},
			}
			workQueueItems = append(workQueueItems, workQueueItem)
		}
	}
	if targetHostname != "" {
		// create listener that proxies to targetHostname
		for _, condition := range rule.Spec.Conditions {
			// validation
			if rule.Spec.Certificate != "" && condition.Hostname == "" {
				return []WorkQueueItem{}, fmt.Errorf("Validation error: rule with certificate, but without a hostname condition - ignoring rule")

			}
			if condition.Hostname != "" || condition.Prefix != "" {
				workQueueItem := WorkQueueItem{
					Action: "createListener",
					ListenerParams: ListenerParams{
						Name:           rule.Metadata.Name,
						TargetHostname: targetHostname,
						Conditions: Conditions{
							Hostname: condition.Hostname,
							Prefix:   condition.Prefix,
							Methods:  condition.Methods,
						},
					},
				}
				// add auth info to parameter
				if rule.Spec.Auth.JwtProvider != "" {
					object, err := x.getObject("jwtProvider", rule.Spec.Auth.JwtProvider)
					workQueueItem.ListenerParams.Auth = Auth{
						JwtProvider: rule.Spec.Auth.JwtProvider,
						Issuer:      object.Data.(pkgApi.JwtProvider).Spec.Issuer,
						Forward:     object.Data.(pkgApi.JwtProvider).Spec.Forward,
						RemoteJwks:  object.Data.(pkgApi.JwtProvider).Spec.RemoteJwks,
					}
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
	object, err := x.s.GetObject(filename)
	if err != nil {
		return []WorkQueueItem{}, fmt.Errorf("Couldn't get new rule from storage: %s", err)
	}
	if object.Kind == "rule" {
		rule := object.Data.(pkgApi.Rule)
		newItems, err := x.ImportRule(rule)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return newItems, nil
	}
	if object.Kind == "jwtProvider" {
		newItems, err := x.ImportObject(object)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new object: %s", err)
		}
		return newItems, nil
	}
	return []WorkQueueItem{}, nil
}
func (x *XDS) deleteObject(filename string) ([]WorkQueueItem, error) {
	object, err := x.s.GetCachedObjectName(filename)
	if err != nil {
		return []WorkQueueItem{}, fmt.Errorf("Couldn't get new rule from storage cache: %s", err)
	}
	if object.Kind == "rule" {
		rule := object.Data.(pkgApi.Rule)
		newItems, err := x.RemoveRule(rule)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't remove rule: %s", err)
		}
		// delete cache entry
		x.s.DeleteCachedObject(filename)
		return newItems, nil
	}
	return []WorkQueueItem{}, nil

}
