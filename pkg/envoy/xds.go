package envoy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/google/go-cmp/cmp"
	pkgApi "github.com/in4it/roxprox/pkg/api"
	storage "github.com/in4it/roxprox/pkg/storage"
	"github.com/in4it/roxprox/proto/notification"
	"github.com/juju/loggo"
	"google.golang.org/grpc"
)

var logger = loggo.GetLogger("xds")

type XDS struct {
	s              storage.Storage
	objects        []pkgApi.Object
	objectsPending []pkgApi.Object
	workQueue      *WorkQueue
	acmeContact    string
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

	server := xds.NewServer(context.Background(), x.workQueue.InitCache(), x.workQueue.InitCallback())
	if port != "" {
		grpcServer := grpc.NewServer()
		lis, _ := net.Listen("tcp", ":"+port)

		discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
		endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
		clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, server)
		routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, server)
		listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, server)
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
			x.objects = append(x.objects, object)
			newitems, err := x.ImportObject(object)
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
	action := x.getAction(rule.Metadata.Name, rule.Spec.Actions)
	for _, condition := range rule.Spec.Conditions {
		// get listener parameters
		listenerParams := x.getListenerParams(action, condition)
		tlsParams := TLSParams{}
		if rule.Spec.Certificate != "" {
			tlsParams = TLSParams{
				Name: rule.Metadata.Name,
			}
		}
		if rule.Spec.Auth.JwtProvider != "" {
			listenerParams.Auth = Auth{
				JwtProvider: rule.Spec.Auth.JwtProvider,
			}
		}
		// check whether we delete the matching rule
		if x.s.CountCachedObjectByCondition(condition, rule.Spec.Actions) > expectedRules {
			// If there is only 1 match, then we're not going to remove the rule condition
			logger.Debugf("Not removing rule with conditions %s %s%s%s (is identical to other condition in other rule)", condition.Hostname, condition.Prefix, condition.Path, condition.Regex)
		} else {
			conditionsToDelete++

			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action:         "deleteRule",
				ListenerParams: listenerParams,
				TLSParams:      tlsParams,
			})
		}
		// check whether we delete the JWT rule
		if x.s.CountCachedJwtRulesByCondition(condition, rule.Spec.Auth.JwtProvider) > expectedRules {
			logger.Debugf("Not removing JWT rule with provider %s and conditions %s %s%s%s (is identical to other condition in other rule)", rule.Spec.Auth.JwtProvider, condition.Hostname, condition.Prefix, condition.Path, condition.Regex)
		} else {
			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action:         "deleteJwtRule",
				ListenerParams: listenerParams,
				TLSParams:      tlsParams,
			})
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
	switch object.Kind {
	case "rule":
		rule := object.Data.(pkgApi.Rule)
		// add new rules
		items, err := x.ImportRule(rule)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "jwtProvider":
		jwtProvider := object.Data.(pkgApi.JwtProvider)
		items, err := x.importJwtProvider(jwtProvider)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "authzFilter":
		authzFilter := object.Data.(pkgApi.AuthzFilter)
		items, err := x.importAuthzFilter(authzFilter)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "tracing":
		tracing := object.Data.(pkgApi.Tracing)
		items, err := x.importTracing(tracing)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "compression":
		compression := object.Data.(pkgApi.Compression)
		items, err := x.importCompression(compression)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "accessLogServer":
		accessLogServer := object.Data.(pkgApi.AccessLogServer)
		items, err := x.importAccessLogServer(accessLogServer)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "rateLimit":
		rateLimit := object.Data.(pkgApi.RateLimit)
		items, err := x.importRateLimit(rateLimit)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	case "mTLS":
		mTLS := object.Data.(pkgApi.MTLS)
		items, err := x.importMTLS(mTLS)
		if err != nil {
			return []WorkQueueItem{}, fmt.Errorf("Couldn't import new rule: %s", err)
		}
		return items, nil
	}

	return []WorkQueueItem{}, nil
}

func (x *XDS) importAuthzFilter(authzFilter pkgApi.AuthzFilter) ([]WorkQueueItem, error) {
	return []WorkQueueItem{
		{
			Action: "createCluster",
			ClusterParams: ClusterParams{
				Name:           "authzFilter_" + authzFilter.Metadata.Name,
				TargetHostname: authzFilter.Spec.Hostname,
				Port:           authzFilter.Spec.Port,
				HTTP2:          true,
			},
		},
		{
			Action: "updateListenersWithAuthzFilter",
			ListenerParams: ListenerParams{
				Name: "authzFilter_" + authzFilter.Metadata.Name,
				Authz: Authz{
					Timeout:          authzFilter.Spec.Timeout,
					FailureModeAllow: authzFilter.Spec.FailureModeAllow,
				},
				Listener: ListenerParamsListener{
					MTLS: authzFilter.Spec.Listener.MTLS,
				},
			},
		},
	}, nil
}

func (x *XDS) importTracing(tracing pkgApi.Tracing) ([]WorkQueueItem, error) {
	return []WorkQueueItem{
		{
			Action: "updateListenersWithTracing",
			TracingParams: TracingParams{
				Enabled:         true,
				ClientSampling:  tracing.Spec.ClientSampling,
				RandomSampling:  tracing.Spec.RandomSampling,
				OverallSampling: tracing.Spec.OverallSampling,
				Listener: ListenerParamsListener{
					MTLS: tracing.Spec.Listener.MTLS,
				},
			},
		},
	}, nil
}

func (x *XDS) importCompression(compression pkgApi.Compression) ([]WorkQueueItem, error) {
	return []WorkQueueItem{
		{
			Action: "updateListenersWithCompression",
			CompressionParams: CompressionParams{
				Type:                compression.Spec.Type,
				ContentLength:       compression.Spec.ContentLength,
				ContentType:         compression.Spec.ContentType,
				DisableOnEtagHeader: compression.Spec.DisableOnEtagHeader,
				Listener: ListenerParamsListener{
					MTLS: compression.Spec.Listener.MTLS,
				},
			},
		},
	}, nil
}

func (x *XDS) importAccessLogServer(accessLogServer pkgApi.AccessLogServer) ([]WorkQueueItem, error) {
	return []WorkQueueItem{
		{
			Action: "updateListenersWithAccessLogServer",
			AccessLogServerParams: AccessLogServerParams{
				Name:                           accessLogServer.Metadata.Name,
				AdditionalRequestHeadersToLog:  accessLogServer.Spec.AdditionalRequestHeadersToLog,
				AdditionalResponseHeadersToLog: accessLogServer.Spec.AdditionalResponseHeadersToLog,
				Listener: ListenerParamsListener{
					MTLS: accessLogServer.Spec.Listener.MTLS,
				},
			},
		},
	}, nil
}

func (x *XDS) importRateLimit(rateLimit pkgApi.RateLimit) ([]WorkQueueItem, error) {
	var descriptors []RateLimitDescriptor
	for _, descriptor := range rateLimit.Spec.Descriptors {
		descriptors = append(descriptors, RateLimitDescriptor{
			DestinationCluster: descriptor.DestinationCluster,
			SourceCluster:      descriptor.SourceCluster,
			RemoteAddress:      descriptor.RemoteAddress,
			RequestHeader:      descriptor.RequestHeader,
		})
	}
	return []WorkQueueItem{
		{
			Action: "updateListenersWithRateLimit",
			RateLimitParams: RateLimitParams{
				Name:        rateLimit.Metadata.Name,
				Descriptors: descriptors,
				Listener: ListenerParamsListener{
					MTLS: rateLimit.Spec.Listener.MTLS,
				},
			},
		},
	}, nil
}

func (x *XDS) importMTLS(mTLS pkgApi.MTLS) ([]WorkQueueItem, error) {
	return []WorkQueueItem{
		{
			Action: "updateListenersWithMTLS",
			MTLSParams: MTLSParams{
				Name:                   mTLS.Metadata.Name,
				PrivateKey:             mTLS.Spec.PrivateKey,
				Certificate:            mTLS.Spec.Certificate,
				CACertificate:          mTLS.Spec.CACertificate,
				AllowedSubjectAltNames: mTLS.Spec.AllowedSubjectAltNames,
				AllowedIPRanges:        mTLS.Spec.AllowedIPRanges,
				Port:                   mTLS.Spec.Port,
				EnableProxyProtocol:    mTLS.Spec.EnableProxyProtocol,
			},
			ListenerParams: ListenerParams{
				Listener: ListenerParamsListener{
					MTLS:             mTLS.Metadata.Name,
					Port:             mTLS.Spec.Port,
					StripAnyHostPort: mTLS.Spec.StripAnyHostPort,
				},
			},
		},
	}, nil
}

func (x *XDS) importJwtProvider(jwtProvider pkgApi.JwtProvider) ([]WorkQueueItem, error) {
	logger.Debugf("Found jwtProvider with name %s and jwksUrl %s", jwtProvider.Metadata.Name, jwtProvider.Spec.RemoteJwks)
	u, err := url.Parse(jwtProvider.Spec.RemoteJwks)
	if err != nil {
		return []WorkQueueItem{}, err
	}

	var port int64
	if u.Port() != "" {
		port, err = strconv.ParseInt(u.Port(), 10, 64)
		if err != nil {
			return []WorkQueueItem{}, err
		}
	} else {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return []WorkQueueItem{
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
	}, nil
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
			logger.Tracef("Condition present (hostname: %s prefix: %s path: %s regex: %s methods: %s)",
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
			listenerParams := x.getListenerParams(action, cachedCondition)
			tlsParams := TLSParams{}
			if cachedRule.Spec.Certificate != "" {
				tlsParams = TLSParams{
					Name: cachedRule.Metadata.Name,
				}
			}
			if cachedRule.Spec.Auth.JwtProvider != "" {
				listenerParams.Auth = Auth{
					JwtProvider: cachedRule.Spec.Auth.JwtProvider,
				}
			}
			// delete matching rule
			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action:         "deleteRule",
				ListenerParams: listenerParams,
				TLSParams:      tlsParams,
			})
			// check whether we delete the JWT rule
			if x.s.CountCachedJwtRulesByCondition(cachedCondition, cachedRule.Spec.Auth.JwtProvider) > 0 {
				logger.Debugf("Not removing JWT rule with provider %s (is identical to other condition still active)", cachedRule.Spec.Auth.JwtProvider)
			} else {
				workQueueItems = append(workQueueItems, WorkQueueItem{
					Action:         "deleteJwtRule",
					ListenerParams: listenerParams,
					TLSParams:      tlsParams,
				})
			}
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
			if ruleAction.Proxy.HealthCheck.HTTPHealthCheck.Path != "" {
				action.Proxy.HealthCheck.HTTPHealthCheck.Path = ruleAction.Proxy.HealthCheck.HTTPHealthCheck.Path
				action.Proxy.HealthCheck.Timeout = ruleAction.Proxy.HealthCheck.Timeout
				action.Proxy.HealthCheck.Interval = ruleAction.Proxy.HealthCheck.Interval
				action.Proxy.HealthCheck.HealthyThreshold = ruleAction.Proxy.HealthCheck.HealthyThreshold
				action.Proxy.HealthCheck.UnhealthyThreshold = ruleAction.Proxy.HealthCheck.UnhealthyThreshold
				action.Proxy.HealthCheck.UnhealthyInterval = ruleAction.Proxy.HealthCheck.UnhealthyInterval
			}
			if ruleAction.Proxy.EnableWebsockets {
				action.Proxy.EnableWebsockets = ruleAction.Proxy.EnableWebsockets
			}
			if ruleAction.Proxy.PrefixRewrite != "" {
				action.Proxy.PrefixRewrite = ruleAction.Proxy.PrefixRewrite
			}
			if ruleAction.Proxy.RegexRewrite.Regex != "" {
				action.Proxy.RegexRewrite.Regex = ruleAction.Proxy.RegexRewrite.Regex
				action.Proxy.RegexRewrite.Substitution = ruleAction.Proxy.RegexRewrite.Substitution
			}
		} else if ruleAction.DirectResponse.Status > 0 {
			action.Type = "directResponse"
			action.RuleName = ruleName
			action.DirectResponse.Status = ruleAction.DirectResponse.Status
			action.DirectResponse.Body = ruleAction.DirectResponse.Body
		}
	}
	return action
}
func (x *XDS) getListenerParams(action Action, condition pkgApi.RuleConditions) ListenerParams {
	switch action.Type {
	case "proxy":
		return ListenerParams{
			Name:             action.RuleName,
			TargetHostname:   action.Proxy.TargetHostname,
			EnableWebSockets: action.Proxy.EnableWebsockets,
			PrefixRewrite:    action.Proxy.PrefixRewrite,
			RegexRewrite:     action.Proxy.RegexRewrite,
			Conditions: Conditions{
				Hostname: condition.Hostname,
				Prefix:   condition.Prefix,
				Path:     condition.Path,
				Regex:    condition.Regex,
				Methods:  condition.Methods,
			},
		}
	case "directResponse":
		return ListenerParams{
			Name: action.RuleName,
			DirectResponse: DirectResponse{
				Status: action.DirectResponse.Status,
				Body:   action.DirectResponse.Body,
			},
			Conditions: Conditions{
				Hostname: condition.Hostname,
				Prefix:   condition.Prefix,
				Path:     condition.Path,
				Regex:    condition.Regex,
				Methods:  condition.Methods,
			},
		}
	default:
		return ListenerParams{}
	}
}
func (x *XDS) getClusterParams(action Action) ClusterParams {
	return ClusterParams{
		Name:           action.RuleName,
		TargetHostname: action.Proxy.TargetHostname,
		Port:           action.Proxy.Port,
		HealthCheck:    action.Proxy.HealthCheck,
	}
}
func (x *XDS) getAuthParams(jwtProviderName string, jwtProvider pkgApi.JwtProvider) Auth {
	return Auth{
		JwtProvider: jwtProviderName,
		Issuer:      jwtProvider.Spec.Issuer,
		Forward:     jwtProvider.Spec.Forward,
		RemoteJwks:  jwtProvider.Spec.RemoteJwks,
		Listener: ListenerParamsListener{
			MTLS: jwtProvider.Spec.Listener.MTLS,
		},
	}
}
func (x *XDS) getMTLSListenerParams(mTLSParams pkgApi.MTLS) ListenerParamsListener {
	return ListenerParamsListener{
		MTLS: mTLSParams.Metadata.Name,
		Port: mTLSParams.Spec.Port,
	}
}

func (x *XDS) ImportRule(rule pkgApi.Rule) ([]WorkQueueItem, error) {
	var workQueueItems []WorkQueueItem
	action := x.getAction(rule.Metadata.Name, rule.Spec.Actions)
	createRuleType := ""
	// create cluster
	switch action.Type {
	case "proxy":
		workQueueItem := WorkQueueItem{
			Action:        "createCluster",
			ClusterParams: x.getClusterParams(action),
		}
		workQueueItems = append(workQueueItems, workQueueItem)
		createRuleType = "createRule"
	case "directResponse":
		createRuleType = "createRuleWithoutCluster"
	default:
		logger.Debugf("Rule without action: %+v", rule)
	}
	// create listener that proxies to targetHostname
	for _, condition := range rule.Spec.Conditions {
		// validation
		if rule.Spec.Certificate != "" && condition.Hostname == "" {
			return []WorkQueueItem{}, fmt.Errorf("Validation error: rule with certificate, but without a hostname condition - ignoring rule")
		}
		if condition.Hostname != "" || condition.Prefix != "" || condition.Path != "" || condition.Regex != "" {
			listenerParams := x.getListenerParams(action, condition)
			if rule.Spec.Listener.MTLS != "" {
				object, err := x.getObject("mTLS", rule.Spec.Listener.MTLS)
				if err != nil {
					logger.Infof("Could not set Listener parameters: mTLS not found (error: %s)", err)
					return workQueueItems, err
				}
				listenerParams.Listener = x.getMTLSListenerParams(object.Data.(pkgApi.MTLS))
			}
			if rule.Spec.Auth.JwtProvider != "" {
				object, err := x.getObject("jwtProvider", rule.Spec.Auth.JwtProvider)
				if err != nil {
					logger.Infof("Could not set Auth parameters: jwtprovider not found (error: %s)", err)
					return workQueueItems, err
				} else {
					listenerParams.Auth = x.getAuthParams(rule.Spec.Auth.JwtProvider, object.Data.(pkgApi.JwtProvider))
				}
				workQueueItems = append(workQueueItems, []WorkQueueItem{
					{
						Action:         createRuleType, // createRule or createRuleWithoutCluster
						ListenerParams: listenerParams,
						TLSParams:      TLSParams{},
					},
					{
						Action:         "updateListenerWithJwtProvider",
						ListenerParams: listenerParams,
					},
					{
						Action:         "createJwtRule",
						ListenerParams: listenerParams,
						TLSParams:      TLSParams{},
					},
				}...)
			} else {
				workQueueItems = append(workQueueItems, WorkQueueItem{
					Action:         createRuleType, // createRule or createRuleWithoutCluster
					ListenerParams: listenerParams,
					TLSParams:      TLSParams{},
				})
			}

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
					createRuleKey := -1
					for k, v := range workQueueItems {
						if v.Action == "createRule" {
							createRuleKey = k
						}
					}
					if createRuleKey != -1 {
						workQueueItemTLS := workQueueItems[createRuleKey]
						workQueueItemTLS.Action = createRuleType // createRule or createRuleWithoutCluster
						workQueueItemTLS.TLSParams = TLSParams{
							Name:       rule.Metadata.Name,
							CertBundle: certBundle,
							PrivateKey: privateKeyPem,
							Domain:     workQueueItems[createRuleKey].ListenerParams.Conditions.Hostname,
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

//ReceiveNotification receives notification items and will process them
func (x *XDS) ReceiveNotification(notifications []*notification.NotificationRequest_NotificationItem) error {
	var (
		workQueueItems []WorkQueueItem
	)

	for _, v := range notifications {
		if v.EventName == "ObjectCreated:Put" {
			newItems, err := x.putObject(v.Filename)
			if err != nil {
				return err
			}
			workQueueItems = append(workQueueItems, newItems...)
		} else if v.EventName == "ObjectRemoved:Delete" {
			newItems, err := x.deleteObject(v.Filename)
			if err != nil {
				return err
			}
			workQueueItems = append(workQueueItems, newItems...)
		}
	}

	if len(workQueueItems) > 0 {
		_, err := x.workQueue.Submit(workQueueItems)
		if err != nil {
			return fmt.Errorf("ReceiveFromQueue Error while Submitting WorkQueue: %s", err)
		}

	}
	return nil
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
	x.addObjects(objects)

	// check pending objects (whether a dependency is now resolved)
	objectsPending := x.objectsPending
	for k, object := range objectsPending {
		unresolvedDependencies := x.getObjectUnresolvedDependencies(object)
		if len(unresolvedDependencies) == 0 {
			logger.Debugf("Dependency is now resolved for: %s", object.Metadata.Name)
			newItems, err := x.ImportObject(object)
			if err != nil {
				return workQueueItems, fmt.Errorf("Couldn't import new object: %s", err)
			}
			workQueueItems = append(workQueueItems, newItems...)
			// delete object from objectsPending
			if len(x.objectsPending) == 1 {
				x.objectsPending = []pkgApi.Object{}
			} else {
				x.objectsPending = append(x.objectsPending[:k], x.objectsPending[k+1:]...)
			}
		}
	}

	// add new objects
	for _, object := range objects {
		unresolvedDependencies := x.getObjectUnresolvedDependencies(object)
		if len(unresolvedDependencies) != 0 {
			logger.Debugf("Unresolved dependency for %s (moving to pending queue)", object.Metadata.Name)
			x.objectsPending = append(x.objectsPending, object)
		} else {
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
	x.deleteObjects(x.objectToValue(objects))
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
func (x *XDS) objectToValue(objects []*pkgApi.Object) []pkgApi.Object {
	var objectsVal []pkgApi.Object
	for _, object := range objects {
		objectsVal = append(objectsVal, *object)
	}
	return objectsVal
}
func (x *XDS) addObjects(objects []pkgApi.Object) {
	x.deleteObjects(objects)
	x.objects = append(x.objects, objects...)
}
func (x *XDS) deleteObjects(objects []pkgApi.Object) {
	for _, object := range objects {
		deleteObject := -1
		for k, curObject := range x.objects {
			if object.Metadata.Name == curObject.Metadata.Name {
				deleteObject = k
			}
		}
		if deleteObject != -1 {
			logger.Tracef("Deleting object from objects list: %s", x.objects[deleteObject].Metadata.Name)
			if len(x.objects) == 1 {
				x.objects = []pkgApi.Object{}
			} else {
				x.objects = append(x.objects[:deleteObject], x.objects[deleteObject+1:]...)
			}
		}
	}
}
func (x *XDS) getObjectUnresolvedDependencies(object pkgApi.Object) []ObjectDependency {
	var dependencies []ObjectDependency
	if object.Kind == "rule" {
		rule := object.Data.(pkgApi.Rule)
		if rule.Spec.Auth.JwtProvider != "" {
			_, err := x.getObject("jwtProvider", rule.Spec.Auth.JwtProvider)
			if err != nil {
				dependencies = append(dependencies, ObjectDependency{
					Type: "jwtProvider",
					Name: rule.Spec.Auth.JwtProvider,
				})
			}
		}
	}
	return dependencies
}
