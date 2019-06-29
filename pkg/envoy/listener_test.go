package envoy

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/juju/loggo"
)

func TestDomainAlreadyExists(t *testing.T) {

	l := newListener()
	var cache WorkQueueCache
	params1 := ListenerParams{
		Name:           "test_1",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Prefix:   "/test1",
		},
	}
	params2 := ListenerParams{
		Name:           "test_2",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Prefix:   "/test2",
		},
	}
	paramsTLS1 := TLSParams{}
	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)
	err := l.updateListener(&cache, params2, paramsTLS1)

	if len(cache.listeners) == 0 {
		t.Errorf("Listener is empty (got %d)", len(cache.listeners))
		return
	}
	cachedListener := cache.listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		t.Errorf("Expected l_http (got %s)", cachedListener.Name)
		return
	}

	manager, err := l.getListenerHTTPConnectionManager(cachedListener)
	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	if len(routeSpecifier.RouteConfig.VirtualHosts) == 0 {
		t.Errorf("Should have more than 0 virtualhosts")
		return
	}
	if len(routeSpecifier.RouteConfig.VirtualHosts[0].Domains) != 1 {
		t.Errorf("Should have 1 domain")
		return
	}
	if routeSpecifier.RouteConfig.VirtualHosts[0].Domains[0] != "hostname1.example.com" {
		t.Errorf("Only domain in virtualhost should be hostname1.example.com")
		return
	}
}

func TestUpdateListener(t *testing.T) {
	// set debug loglevel
	logger.SetLogLevel(loggo.DEBUG)
	l := newListener()
	var cache WorkQueueCache
	params1 := ListenerParams{
		Name:           "test_1",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Prefix:   "/test1",
		},
	}
	params2 := ListenerParams{
		Name:           "test_2",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname2.example.com",
			Prefix:   "/test2",
			Methods:  []string{"GET", "POST"},
		},
	}
	params3 := ListenerParams{
		Name:           "test_3",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname2.example.com",
			Prefix:   "/test3",
		},
		Auth: Auth{
			JwtProvider: "testJwt",
			Issuer:      "http://issuer.example.com",
			Forward:     true,
			RemoteJwks:  "https://remotejwks.example.com",
		},
	}
	params4 := ListenerParams{
		Name:           "test_4",
		Protocol:       "tls",
		TargetHostname: "www.test-tls.inv",
		Conditions: Conditions{
			Hostname: "hostname4.example.com",
			Prefix:   "/test4",
		},
		Auth: Auth{
			JwtProvider: "testJwt",
			Issuer:      "http://issuer.example.com",
			Forward:     true,
			RemoteJwks:  "https://remotejwks.example.com",
		},
	}
	params5 := ListenerParams{
		Name:           "test_5",
		Protocol:       "tls",
		TargetHostname: "www.test-tls2.inv",
		Conditions: Conditions{
			Hostname: "hostname5.example.com",
			Prefix:   "/test5",
		},
		Auth: Auth{
			JwtProvider: "testJwt2",
			Issuer:      "http://issuer2.example.com",
			Forward:     true,
			RemoteJwks:  "https://remotejwks2.example.com",
		},
	}
	paramsTLS1 := TLSParams{}
	paramsTLS4 := TLSParams{
		Name:       "test-tls",
		CertBundle: "certbundle",
		PrivateKey: "privateKey",
		Domain:     "hostname4.example.com",
	}
	paramsTLS5 := TLSParams{
		Name:       "test-tls2",
		CertBundle: "certbundle2",
		PrivateKey: "privateKey2",
		Domain:     "hostname5.example.com",
	}
	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)

	// validate domain 1
	if err := validateDomain(cache.listeners, params1); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}

	// update listener with domain 2

	if err := l.updateListener(&cache, params2, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	// validate domain 1 and 2
	if err := validateDomain(cache.listeners, params1); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	if err := validateDomain(cache.listeners, params2); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}

	// add domain 3
	if err := l.updateListener(&cache, params3, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// validate domain 3
	if err := validateDomain(cache.listeners, params3); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}

	// add domain 4 (TLS)
	TLSListener := l.createListener(params4, paramsTLS4)
	cache.listeners = append(cache.listeners, TLSListener)

	// validate domain 4 (TLS)
	if err := validateDomainTLS(cache.listeners, params4, paramsTLS4); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}

	// add domain 5 (TLS)
	if err := l.updateListener(&cache, params5, paramsTLS5); err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	// validate domain 5 (TLS)
	if err := validateDomainTLS(cache.listeners, params5, paramsTLS5); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
}
func validateDomainTLS(listeners []cache.Resource, params ListenerParams, tlsParams TLSParams) error {
	l := newListener()
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}
	cachedListener := listeners[1].(*api.Listener)
	if cachedListener.Name != "l_tls" {
		return fmt.Errorf("Expected l_tls (got %s)", cachedListener.Name)
	}

	manager, err := l.getListenerHTTPConnectionManagerTLS(cachedListener, params.Conditions.Hostname)
	if err != nil {
		return err
	}

	if err := validateAttributes(manager, params); err != nil {
		return err
	}

	filterId := l.getFilterChainId(cachedListener.FilterChains, params.Conditions.Hostname)

	if filterId == -1 {
		return fmt.Errorf("Filter not found for domain %s", params.Conditions.Hostname)
	}

	if len(cachedListener.FilterChains[filterId].TlsContext.CommonTlsContext.TlsCertificates) == 0 {
		return fmt.Errorf("No certificates found in filter chain for domain %s", params.Conditions.Hostname)
	}
	tlsBundle := cachedListener.FilterChains[filterId].TlsContext.CommonTlsContext.TlsCertificates[0].CertificateChain.Specifier.(*core.DataSource_InlineString).InlineString
	privateKey := cachedListener.FilterChains[filterId].TlsContext.CommonTlsContext.TlsCertificates[0].PrivateKey.Specifier.(*core.DataSource_InlineString).InlineString

	if tlsBundle != tlsParams.CertBundle {
		return fmt.Errorf("TLS bundle not found. Got: %s, Expected: %s", tlsBundle, tlsParams.CertBundle)
	}
	if privateKey != tlsParams.PrivateKey {
		return fmt.Errorf("Private key not found. Got: %s", privateKey)
	}
	logger.Debugf("Key and cert found for domain %s", params.Conditions.Hostname)

	return nil
}

func validateDomain(listeners []cache.Resource, params ListenerParams) error {
	l := newListener()
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}
	cachedListener := listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		return fmt.Errorf("Expected l_http (got %s)", cachedListener.Name)
	}

	manager, err := l.getListenerHTTPConnectionManager(cachedListener)
	if err != nil {
		return err
	}
	return validateAttributes(manager, params)
}

func validateAttributes(manager hcm.HttpConnectionManager, params ListenerParams) error {
	l := newListener()
	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		return fmt.Errorf("Error: %s", err)
	}

	domainFound := false
	prefixFound := false
	methodsFound := false

	if params.Conditions.Hostname == "" {
		params.Conditions.Hostname = "*"
	}
	if params.Conditions.Prefix == "/" {
		params.Conditions.Prefix = "/"
	}

	for _, virtualhost := range routeSpecifier.RouteConfig.VirtualHosts {
		for _, domain := range virtualhost.Domains {
			if domain == params.Conditions.Hostname {
				domainFound = true
				for _, r := range virtualhost.Routes {
					if r.Match.PathSpecifier.(*route.RouteMatch_Prefix).Prefix == params.Conditions.Prefix {
						prefixFound = true
					}
					if len(params.Conditions.Methods) > 0 {
						methodsInHeader := []string{}
						for _, v := range r.Match.Headers {
							if v.Name == ":method" {
								methodsInHeader = append(methodsInHeader, v.GetExactMatch())
							}
						}
						sort.Strings(methodsInHeader)
						sort.Strings(params.Conditions.Methods)
						if testEqualityString(params.Conditions.Methods, methodsInHeader) {
							methodsFound = true
						}
					}

				}
			}
		}
	}

	if domainFound != true {
		return fmt.Errorf("Domain not found: %s", params.Conditions.Hostname)
	}
	logger.Debugf("Domain found: %s", params.Conditions.Hostname)

	if prefixFound != true {
		return fmt.Errorf("Prefix not found: %s", params.Conditions.Prefix)
	}
	logger.Debugf("Prefix found: %s", params.Conditions.Prefix)

	if len(params.Conditions.Methods) > 0 && !methodsFound {
		return fmt.Errorf("Methods not found: %s", strings.Join(params.Conditions.Methods, ","))

	}
	if len(params.Conditions.Methods) > 0 {
		logger.Debugf("Methods found: %s", strings.Join(params.Conditions.Methods, ","))
	}

	return nil
}

func testEqualityString(a, b []string) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
