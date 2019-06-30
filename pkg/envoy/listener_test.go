package envoy

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	jwtAuth "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/jwt_authn/v2alpha"
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

func TestDoubleEntry(t *testing.T) {
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
			Hostname: "hostname1.example.com",
			Prefix:   "/test2",
		},
	}
	paramsTLS1 := TLSParams{}

	// create first domain
	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)
	// update listener with domain 2
	if err := l.updateListener(&cache, params1, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	if err := l.updateListener(&cache, params2, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	cachedListener := cache.listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		t.Errorf("Expected l_http (got %s)", cachedListener.Name)
		return
	}

	manager, err := l.getListenerHTTPConnectionManager(cachedListener)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	domainFound := false

	for _, virtualhost := range routeSpecifier.RouteConfig.VirtualHosts {
		for _, domain := range virtualhost.Domains {
			if domain == params1.Conditions.Hostname {
				domainFound = true
				if len(virtualhost.Routes) != 2 {
					t.Errorf("Expected to only have 2 routes. %+v", virtualhost.Routes)
					return
				}
			}
		}
	}
	if !domainFound {
		t.Errorf("Domain not found in virtualhost")
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
	paramsTLS1 := TLSParams{}
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
	paramsTLS4 := TLSParams{
		Name:       "test-tls",
		CertBundle: "certbundle",
		PrivateKey: "privateKey",
		Domain:     "hostname4.example.com",
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
	paramsTLS5 := TLSParams{
		Name:       "test-tls2",
		CertBundle: "certbundle2",
		PrivateKey: "privateKey2",
		Domain:     "hostname5.example.com",
	}
	paramsTLS5New := TLSParams{
		Name:       "test-tls2",
		CertBundle: "certbundle3",
		PrivateKey: "privateKey3",
		Domain:     "hostname5.example.com",
	}
	params6 := ListenerParams{
		Auth: Auth{
			JwtProvider: "testJwt2",
			Issuer:      "http://issuer3.example.com",
			Forward:     true,
			RemoteJwks:  "https://remotejwks3.example.com",
		},
	}
	challenge1 := ChallengeParams{
		Name:   "cert1",
		Domain: "example.com",
		Token:  "abc-mytoken-123",
		Body:   "this-is-the-token-body",
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

	// update TLS cert of domain 5
	if err := l.updateListenerWithNewCert(&cache, paramsTLS5New); err != nil {
		t.Errorf("Updating tls cert failed: %s", err)
		return
	}

	// validate domain 5 (TLSNew)
	if err := validateDomainTLS(cache.listeners, params5, paramsTLS5New); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}

	// update jwt provider
	if err := l.updateListenerWithJwtProvider(&cache, params6); err != nil {
		t.Errorf("Updating jwt provider failed: %s", err)
		return
	}
	if err := validateJWTProvider(cache.listeners, params6.Auth); err != nil {
		t.Errorf("JWTProvider validation failed: %s", err)
		return
	}
	// update challenge
	if err := l.updateListenerWithChallenge(&cache, challenge1); err != nil {
		t.Errorf("Updating challenge failed: %s", err)
		return
	}
	if err := validateChallenge(cache.listeners, challenge1); err != nil {
		t.Errorf("Challenge validation failed: %s", err)
		return
	}
}

func validateChallenge(listeners []cache.Resource, params ChallengeParams) error {
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

	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		return fmt.Errorf("Error: %s", err)
	}

	challengeFound := false

	for _, virtualhost := range routeSpecifier.RouteConfig.VirtualHosts {
		for _, domain := range virtualhost.Domains {
			if domain == "*" {
				for _, r := range virtualhost.Routes {
					if r.Match.PathSpecifier.(*route.RouteMatch_Path).Path == "/.well-known/acme-challenge/"+params.Token {
						challengeFound = true
						if r.Action.(*route.Route_DirectResponse).DirectResponse.Status != 200 {
							return fmt.Errorf("Challenge has wrong http response")
						}
						if r.Action.(*route.Route_DirectResponse).DirectResponse.Body.Specifier.(*core.DataSource_InlineString).InlineString != params.Body {
							return fmt.Errorf("Challenge has wrong http body")
						}
					}
				}
			}
		}
	}
	if !challengeFound {
		return fmt.Errorf("Challenge not found: %s", params.Token)
	}
	logger.Debugf("Challenge %s found", params.Token)
	return nil
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

	return validateAttributes(manager, params)
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

	return validateJWT(manager, params)

}

func validateJWTProvider(listeners []cache.Resource, auth Auth) error {
	l := newListener()
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}

	for _, cachedListenerResource := range listeners {
		cachedListener := cachedListenerResource.(*api.Listener)

		if cachedListener.Name == "l_http" {
			manager, err := l.getListenerHTTPConnectionManager(cachedListener)
			if err != nil {
				return err
			}
			jwtConfig, err := l.getListenerHTTPFilter(manager.HttpFilters)
			if err != nil {
				return err
			}
			err = validateJWTProviderWithJWTConfig(jwtConfig, auth, cachedListener.Name)
		} else if cachedListener.Name == "l_tls" {
			for _, filterChain := range cachedListener.FilterChains {
				if len(filterChain.Filters) == 0 {
					return fmt.Errorf("No filters found in listener %s", cachedListener.Name)
				}
				manager, err := l.getManager((filterChain.Filters[0].ConfigType).(*listener.Filter_TypedConfig))
				if err != nil {
					return fmt.Errorf("Could not extract manager from listener %s", cachedListener.Name)
				}
				jwtConfig, err := l.getListenerHTTPFilter(manager.HttpFilters)
				if err != nil {
					return err
				}
				err = validateJWTProviderWithJWTConfig(jwtConfig, auth, cachedListener.Name)
			}
		} else {
			return fmt.Errorf("Unknown listener %s", cachedListener.Name)
		}
	}

	return nil
}

func validateJWTProviderWithJWTConfig(jwtConfig jwtAuth.JwtAuthentication, auth Auth, listenerName string) error {
	providerFound := false
	for k := range jwtConfig.Providers {
		if k == auth.JwtProvider {
			providerFound = true
		}
	}
	if !providerFound {
		return fmt.Errorf("JWTProvider %s not found in listener %s", auth.JwtProvider, listenerName)
	}
	logger.Debugf("JWTProvider %s found in listener %s", auth.JwtProvider, listenerName)

	if jwtConfig.Providers[auth.JwtProvider].Issuer != auth.Issuer {
		return fmt.Errorf("Issuer %s not found (got: %s)", auth.Issuer, jwtConfig.Providers[auth.JwtProvider].Issuer)
	}
	if jwtConfig.Providers[auth.JwtProvider].JwksSourceSpecifier.(*jwtAuth.JwtProvider_RemoteJwks).RemoteJwks.HttpUri.Uri != auth.RemoteJwks {
		return fmt.Errorf("Issuer %s not found (got: %s)", auth.RemoteJwks, jwtConfig.Providers[auth.JwtProvider].JwksSourceSpecifier.(*jwtAuth.JwtProvider_RemoteJwks).RemoteJwks.HttpUri.Uri)
	}
	logger.Debugf("JWT Issuer found found in listener %s", listenerName)

	return nil
}

func validateJWT(manager hcm.HttpConnectionManager, params ListenerParams) error {
	l := newListener()
	// validate jwt
	if params.Auth.JwtProvider != "" {
		jwtConfig, err := l.getListenerHTTPFilter(manager.HttpFilters)
		if err != nil {
			return err
		}
		providerFound := false
		for k := range jwtConfig.Providers {
			if k == params.Auth.JwtProvider {
				providerFound = true
			}
		}
		if !providerFound {
			return fmt.Errorf("JWT provider not found")
		}
		logger.Debugf("JWT provider found")

		prefixFound := false
		domainFound := false
		for _, rule := range jwtConfig.Rules {
			if rule.Match.PathSpecifier.(*route.RouteMatch_Prefix).Prefix == params.Conditions.Prefix {
				prefixFound = true
				for _, header := range rule.Match.Headers {
					if header.Name == ":authority" && header.HeaderMatchSpecifier.(*route.HeaderMatcher_ExactMatch).ExactMatch == params.Conditions.Hostname {
						domainFound = true
					}
				}
			}
		}

		if !prefixFound {
			return fmt.Errorf("JWT: prefix not found")
		}
		if params.Conditions.Hostname != "" && !domainFound {
			return fmt.Errorf("JWT: domain not found")
		}

		logger.Debugf("Prefix & domain found")
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
