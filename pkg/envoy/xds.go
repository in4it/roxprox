package envoy

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	xds "github.com/envoyproxy/go-control-plane/pkg/server"
	pkgApi "github.com/in4it/envoy-autocert/pkg/api"
	storage "github.com/in4it/envoy-autocert/pkg/storage"
	"github.com/juju/loggo"
	"google.golang.org/grpc"
)

var logger = loggo.GetLogger("xds")

type XDS struct {
	s           storage.Storage
	rules       []pkgApi.Rule
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
func (x *XDS) ImportRules() error {
	var (
		workQueueItems []WorkQueueItem
		err            error
	)
	x.rules, err = x.s.ListRules()
	if err != nil {
		return err
	}

	for _, rule := range x.rules {
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
				if condition.Hostname != "" || condition.Prefix != "" {
					workQueueItem := WorkQueueItem{
						Action: "createListener",
						ListenerParams: ListenerParams{
							Name:           rule.Metadata.Name,
							TargetHostname: targetHostname,
							Conditions: Conditions{
								Hostname: condition.Hostname,
								Prefix:   condition.Prefix,
							},
						},
					}
					workQueueItems = append(workQueueItems, workQueueItem)
					// TLS listener
					certBundle, err := x.s.GetCertBundle(rule.Metadata.Name)
					if err != nil && err != x.s.GetError("errNotExist") {
						return err
					}
					if err != nil && err == x.s.GetError("errNotExist") {
						// TODO: add to list for creation
						logger.Debugf("Certificate not found, needs to be created")
					}
					if err == nil {
						logger.Debugf("Certificate found, adding TLS")
						privateKeyPem, err := x.s.GetPrivateKeyPem(rule.Metadata.Name)
						if err != nil {
							return err
						}
						workQueueItemTLS := workQueueItem
						workQueueItemTLS.Action = "createTLSListener"
						workQueueItemTLS.TLSParams = TLSParams{
							Name:       rule.Metadata.Name,
							CertBundle: certBundle,
							PrivateKey: privateKeyPem,
						}
						workQueueItems = append(workQueueItems, workQueueItemTLS)
					}

				}
			}
		}

	}

	x.workQueue.Submit(workQueueItems)

	return nil
}

func (x *XDS) CreateCertsForRules() error {
	var workQueueItems []WorkQueueItem
	// tls certs

	for _, rule := range x.rules {
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
	x.workQueue.Submit(workQueueItems)
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
