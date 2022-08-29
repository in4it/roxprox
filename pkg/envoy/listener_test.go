package envoy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	jwtAuth "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/gogo/protobuf/types"
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

	err := l.updateListener(&cache, params1, paramsTLS1)
	if err != nil {
		t.Errorf("UpdateListener params 1 error: %s", err)
		return
	}
	err = l.updateListener(&cache, params2, paramsTLS1)
	if err != nil {
		t.Errorf("UpdateListener params 2 error: %s", err)
		return
	}

	if len(cache.listeners) == 0 {
		t.Errorf("Listener is empty (got %d)", len(cache.listeners))
		return
	}
	cachedListener := cache.listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		t.Errorf("Expected l_http (got %s)", cachedListener.Name)
		return
	}

	manager, err := getListenerHTTPConnectionManager(cachedListener)
	routeSpecifier, err := getListenerRouteSpecifier(manager)
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
		t.Errorf("Only domain in virtualhost should be hostname1.example.com (got: %+v)", routeSpecifier.RouteConfig.VirtualHosts)
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

	manager, err := getListenerHTTPConnectionManager(cachedListener)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	routeSpecifier, err := getListenerRouteSpecifier(manager)
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
	j := newJwtProvider()
	a := newAuthzFilter()
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
	params7 := ListenerParams{
		Name:           "test_7",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Path:     "/test7",
			Methods:  []string{"POST", "DELETE"},
		},
		Auth: Auth{
			JwtProvider: "testJwt2",
			Issuer:      "http://issuer3.example.com",
			Forward:     true,
			RemoteJwks:  "https://remotejwks3.example.com",
		},
	}
	params8 := ListenerParams{
		Name:           "test_8",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Regex:    "/test8/(.*)",
			Methods:  []string{"POST", "DELETE"},
		},
	}
	params9 := ListenerParams{
		Name: "authzTest",
		Authz: Authz{
			Timeout:          "2s",
			FailureModeAllow: false,
		},
	}
	params10 := ListenerParams{
		Name: "directResponseTest",
		Conditions: Conditions{
			Path:    "/directresponse",
			Methods: []string{"GET"},
		},
		DirectResponse: DirectResponse{
			Status: 200,
			Body:   "OK",
		},
	}
	params11 := ListenerParams{
		Name:           "test_mtls_1",
		Protocol:       "http",
		TargetHostname: "www.test-mtls.inv",
		Conditions: Conditions{
			Hostname: "hostname11.example.com",
			Prefix:   "/test11",
			Methods:  []string{"GET", "POST"},
		},
		Listener: ListenerParamsListener{
			MTLS: "test-mtls",
		},
	}

	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)

	// update listener with domain 1
	if err := l.updateListener(&cache, params1, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}

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
	// add domain 3 (jwt)
	if err := j.UpdateJwtRule(&cache, params3, paramsTLS1); err != nil {
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

	// update listener for domain 4 (TLS)
	if err := l.updateListener(&cache, params4, paramsTLS4); err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	// update listener for domain 4 (jwt)
	if err := j.UpdateJwtRule(&cache, params4, paramsTLS4); err != nil {
		t.Errorf("Error: %s", err)
		return
	}

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

	// update listener for domain 5 (jwt)
	if err := j.UpdateJwtRule(&cache, params5, paramsTLS5); err != nil {
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
	if err := j.updateListenerWithJwtProvider(&cache, params6); err != nil {
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
	// delete route for domain 5
	if err := l.DeleteRoute(&cache, params5, paramsTLS5New); err != nil {
		t.Errorf("Delete route failed: %s", err)
		return
	}
	if err := j.DeleteJwtRule(&cache, params5, paramsTLS5New); err != nil {
		t.Errorf("Delete jwt failed: %s", err)
		return
	}
	// validate domain 5 (TLSNew)
	if err := validateDeleteRoute(cache.listeners, params5, paramsTLS5New, 2 /* active listeners */); err != nil {
		t.Errorf("Delete Validation failed: %s", err)
		return
	}
	// delete route for domain 1
	if err := l.DeleteRoute(&cache, params1, paramsTLS1); err != nil {
		t.Errorf("Delete route failed: %s", err)
		return
	}
	// validate domain 1
	if err := validateDeleteRoute(cache.listeners, params1, paramsTLS1, 2 /* active listeners */); err != nil {
		t.Errorf("Delete Validation failed: %s", err)
		return
	}
	// add domain 7 (methods and path)
	if err := l.updateListener(&cache, params7, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// update listener for domain 7 (jwt)
	if err := j.UpdateJwtRule(&cache, params7, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	// validate domain 7
	if err := validateDomain(cache.listeners, params7); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	// add domain 7 (second time to see if there are no duplicates)
	if err := l.updateListener(&cache, params7, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// validate domain 7
	if err := validateDomain(cache.listeners, params7); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	// add domain 8 (regex support)
	if err := l.updateListener(&cache, params8, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// validate domain 8
	if err := validateDomain(cache.listeners, params8); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	// add authz (should update all listeners)
	if err := a.updateListenersWithAuthzFilter(&cache, params9); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// validate authz
	if err := validateAuthz(cache.listeners, params9); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	// update default HTTP Router filter
	if authzConfig, err := a.getAuthzFilterEncoded(params9); err != nil {
		t.Errorf("getAuthzFilterEncoded error: %s", err)
	} else {
		l.updateDefaultHTTPRouterFilter("envoy.ext_authz", authzConfig)
	}
	// validate new HTTP filters
	if err := validateNewHTTPRouterFilter(l.newHTTPRouterFilter("l_http"), params9); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}

	// update listener with domain 10
	if err := l.updateListener(&cache, params10, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	// validate domain 10
	if err := validateDomain(cache.listeners, params10); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	// mTLS tests
	mTLSListener := l.createListener(params11, paramsTLS1)
	cache.listeners = append(cache.listeners, mTLSListener)
	// add domain 11
	if err := l.updateListener(&cache, params11, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	if err := validateDomain(cache.listeners, params11); err != nil {
		t.Errorf("Validation failed: %s", err)
		return
	}
	// delete route for domain 11
	if err := l.DeleteRoute(&cache, params11, paramsTLS1); err != nil {
		t.Errorf("Delete route failed: %s", err)
		return
	}
	// validate domain 11
	if err := validateDeleteRoute(cache.listeners, params11, paramsTLS1, 3 /* listeners */); err != nil {
		t.Errorf("Delete Validation failed: %s", err)
		return
	}
}

func validateDeleteRoute(listeners []cacheTypes.Resource, params ListenerParams, tlsParams TLSParams, activeListeners int) error {
	if len(listeners) != activeListeners {
		return fmt.Errorf("Expected %d listeners (l_http and l_tls) (got %d)", activeListeners, len(listeners))
	}
	cachedListener := listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		return fmt.Errorf("Expected l_http (got %s)", cachedListener.Name)
	}
	cachedListenerTLS := listeners[1].(*api.Listener)
	if cachedListenerTLS.Name != "l_tls" {
		return fmt.Errorf("Expected l_tls (got %s)", cachedListenerTLS.Name)
	}

	var manager *hcm.HttpConnectionManager
	var err error
	if tlsParams.Name == "" {
		manager, err = getListenerHTTPConnectionManager(cachedListener)
		if err != nil {
			return err
		}
	} else {
		manager, err = getListenerHTTPConnectionManagerTLS(cachedListenerTLS, params.Conditions.Hostname)
		if err != nil {
			return err
		}
	}

	err = validateAttributes(manager, params)

	if err == nil {
		return fmt.Errorf("Expected domain to be deleted, still found")
	}

	if params.Auth.JwtProvider != "" {
		err = validateJWT(manager, params)
		if err == nil {
			return fmt.Errorf("Expected domain to be deleted, still found JWT Rules")
		}
	}

	logger.Debugf("Domain %s with prefix %s not found anymore", params.Conditions.Hostname, params.Conditions.Prefix)

	return nil
}

func validateChallenge(listeners []cacheTypes.Resource, params ChallengeParams) error {
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}
	cachedListener := listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		return fmt.Errorf("Expected l_http (got %s)", cachedListener.Name)
	}

	manager, err := getListenerHTTPConnectionManager(cachedListener)
	if err != nil {
		return err
	}

	routeSpecifier, err := getListenerRouteSpecifier(manager)
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

func validateDomainTLS(listeners []cacheTypes.Resource, params ListenerParams, tlsParams TLSParams) error {
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}
	cachedListener := listeners[1].(*api.Listener)
	if cachedListener.Name != "l_tls" {
		return fmt.Errorf("Expected l_tls (got %s)", cachedListener.Name)
	}

	manager, err := getListenerHTTPConnectionManagerTLS(cachedListener, params.Conditions.Hostname)
	if err != nil {
		return err
	}

	if err := validateAttributes(manager, params); err != nil {
		return err
	}

	filterId := getFilterChainId(cachedListener.FilterChains, params.Conditions.Hostname)

	if filterId == -1 {
		return fmt.Errorf("Filter not found for domain %s", params.Conditions.Hostname)
	}
	tlsContext, err := getTransportSocketDownStreamTlsSocket(cachedListener.FilterChains[filterId].GetTransportSocket().GetConfigType().(*core.TransportSocket_TypedConfig))
	if err != nil {
		panic(err)
	}
	if len(tlsContext.GetCommonTlsContext().GetTlsCertificates()) == 0 {
		return fmt.Errorf("No certificates found in filter chain for domain %s", params.Conditions.Hostname)
	}
	tlsBundle := tlsContext.GetCommonTlsContext().TlsCertificates[0].CertificateChain.Specifier.(*core.DataSource_InlineString).InlineString
	privateKey := tlsContext.GetCommonTlsContext().TlsCertificates[0].PrivateKey.Specifier.(*core.DataSource_InlineString).InlineString

	if tlsBundle != tlsParams.CertBundle {
		return fmt.Errorf("TLS bundle not found. Got: %s, Expected: %s", tlsBundle, tlsParams.CertBundle)
	}
	if privateKey != tlsParams.PrivateKey {
		return fmt.Errorf("Private key not found. Got: %s", privateKey)
	}
	logger.Debugf("Key and cert found for domain %s", params.Conditions.Hostname)

	return nil
}

func validateDomain(listeners []cacheTypes.Resource, params ListenerParams) error {
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}
	var cachedListener *api.Listener
	if params.Listener.MTLS != "" {
		found := false
		for k := range listeners {
			if !found {
				if listeners[k].(*api.Listener).Name == "l_mtls_"+params.Listener.MTLS {
					cachedListener = listeners[k].(*api.Listener)
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("Listener %s not found", "l_mtls_"+params.Listener.MTLS)
		}
	} else {
		cachedListener = listeners[0].(*api.Listener)
		if cachedListener.Name != "l_http" {
			return fmt.Errorf("Expected l_http (got %s)", cachedListener.Name)
		}
	}

	manager, err := getListenerHTTPConnectionManager(cachedListener)
	if err != nil {
		return err
	}
	return validateAttributes(manager, params)
}

func validateAttributes(manager *hcm.HttpConnectionManager, params ListenerParams) error {
	routeSpecifier, err := getListenerRouteSpecifier(manager)
	if err != nil {
		return fmt.Errorf("Error: %s", err)
	}

	domainFound := false
	prefixFound := false
	pathFound := false
	regexFound := false
	directResponseFound := false
	methodsFound := make(map[string]bool)

	if params.Conditions.Hostname == "" {
		params.Conditions.Hostname = "*"
	}

	if params.Conditions.Path == "" && params.Conditions.Prefix == "" {
		params.Conditions.Prefix = "/"
	}

	for _, virtualhost := range routeSpecifier.RouteConfig.VirtualHosts {
		for _, domain := range virtualhost.Domains {
			if domain == params.Conditions.Hostname {
				domainFound = true
				for _, r := range virtualhost.Routes {
					switch reflect.TypeOf(r.Match.PathSpecifier).String() {
					case "*routev3.RouteMatch_Prefix":
						if r.Match.PathSpecifier.(*route.RouteMatch_Prefix).Prefix == params.Conditions.Prefix {
							prefixFound = true
						}
					case "*routev3.RouteMatch_Path":
						if r.Match.PathSpecifier.(*route.RouteMatch_Path).Path == params.Conditions.Path {
							pathFound = true
						}
					case "*routev3.RouteMatch_SafeRegex":
						if r.Match.PathSpecifier.(*route.RouteMatch_SafeRegex).SafeRegex.GetRegex() == params.Conditions.Regex {
							regexFound = true
						}
					default:
						return fmt.Errorf("Match PathSpecifier unknown type %s", reflect.TypeOf(r.Match.PathSpecifier).String())
					}
					if len(params.Conditions.Methods) > 0 {
						for _, v1 := range r.Match.Headers {
							for _, v2 := range params.Conditions.Methods {
								if v1.GetName() == ":method" && v1.GetExactMatch() == v2 {
									methodsFound[v2] = true
								}
							}
						}
					}
					switch reflect.TypeOf(r.Action).String() {
					case "*routev3.Route_Route":
						// do nothing here
					case "*routev3.Route_DirectResponse":
						d := r.Action.(*route.Route_DirectResponse).DirectResponse
						if params.DirectResponse.Status == d.GetStatus() && params.DirectResponse.Body == d.GetBody().GetInlineString() {
							directResponseFound = true
						}
					default:
						return fmt.Errorf("Type is %s", reflect.TypeOf(r.Action).String())
					}
				}
			}
		}
	}

	if domainFound != true {
		return fmt.Errorf("Domain not found: %s", params.Conditions.Hostname)
	}
	logger.Debugf("Domain found: %s", params.Conditions.Hostname)

	if params.Conditions.Path == "" && params.Conditions.Regex == "" && prefixFound != true {
		return fmt.Errorf("Prefix not found: %s", params.Conditions.Prefix)
	}
	logger.Debugf("Prefix found: %s", params.Conditions.Prefix)

	if params.Conditions.Path != "" && pathFound != true {
		return fmt.Errorf("Path not found: %s", params.Conditions.Path)
	}
	logger.Debugf("Path found: %s", params.Conditions.Path)

	if params.Conditions.Regex != "" && regexFound != true {
		return fmt.Errorf("Regex not found: %s", params.Conditions.Regex)
	}
	logger.Debugf("Regex found: %s", params.Conditions.Regex)

	if len(params.Conditions.Methods) > 0 {
		for _, v := range params.Conditions.Methods {
			if _, ok := methodsFound[v]; !ok {
				return fmt.Errorf("Methods not found: %s (expected %s)", v, strings.Join(params.Conditions.Methods, ","))
			}
		}
	}
	if len(params.Conditions.Methods) > 0 {
		logger.Debugf("Methods found: %s", strings.Join(params.Conditions.Methods, ","))
	}

	if params.DirectResponse.Status > 0 && !directResponseFound {
		return fmt.Errorf("Got directresponse parameter, but no directresponse found")
	} else {
		logger.Debugf("Directresponse found found: %d : %s", params.DirectResponse.Status, params.DirectResponse.Body)
	}

	return validateJWT(manager, params)

}

func validateMethods(headers []*route.HeaderMatcher, methods []string) bool {
	methodsInHeader := []string{}
	for _, v := range headers {
		if v.Name == ":method" {
			methodsInHeader = append(methodsInHeader, v.GetExactMatch())
		}
	}
	sort.Strings(methodsInHeader)
	sort.Strings(methods)
	if testEqualityString(methods, methodsInHeader) {
		return true
	}
	return false
}

func validateJWTProvider(listeners []cacheTypes.Resource, auth Auth) error {
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}

	for _, cachedListenerResource := range listeners {
		cachedListener := cachedListenerResource.(*api.Listener)

		if cachedListener.Name == "l_http" {
			manager, err := getListenerHTTPConnectionManager(cachedListener)
			if err != nil {
				return err
			}
			jwtConfig, err := getListenerHTTPFilterJwtAuth(manager.HttpFilters)
			if err != nil {
				return err
			}
			err = validateJWTProviderWithJWTConfig(jwtConfig, auth, cachedListener.Name)
		} else if cachedListener.Name == "l_tls" {
			for _, filterChain := range cachedListener.FilterChains {
				if len(filterChain.Filters) == 0 {
					return fmt.Errorf("No filters found in listener %s", cachedListener.Name)
				}
				manager, err := getManager((filterChain.Filters[getFilterIndexByName(filterChain.Filters, Envoy_HTTP_Filter)].ConfigType).(*api.Filter_TypedConfig))
				if err != nil {
					return fmt.Errorf("Could not extract manager from listener %s", cachedListener.Name)
				}
				jwtConfig, err := getListenerHTTPFilterJwtAuth(manager.HttpFilters)
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

func validateJWTProviderWithJWTConfig(jwtConfig *jwtAuth.JwtAuthentication, auth Auth, listenerName string) error {
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

func validateJWT(manager *hcm.HttpConnectionManager, params ListenerParams) error {
	// validate jwt
	if params.Auth.JwtProvider != "" {
		jwtConfig, err := getListenerHTTPFilterJwtAuth(manager.HttpFilters)
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
		pathFound := false
		regexFound := false
		domainFound := false
		methodsFound := make(map[string]bool)
		matchedEntries := 0
		for _, rule := range jwtConfig.Rules {
			switch reflect.TypeOf(rule.Match.PathSpecifier).String() {
			case "*routev3.RouteMatch_Prefix":
				if rule.Match.PathSpecifier.(*route.RouteMatch_Prefix).Prefix == params.Conditions.Prefix {
					prefixFound = true
				}
			case "*routev3.RouteMatch_Path":
				if rule.Match.PathSpecifier.(*route.RouteMatch_Path).Path == params.Conditions.Path {
					pathFound = true
				}
			case "*routev3.RouteMatch_SafeRegex":
				if rule.Match.PathSpecifier.(*route.RouteMatch_SafeRegex).SafeRegex.GetRegex() == params.Conditions.Regex {
					regexFound = true
				}
			default:
				return fmt.Errorf("Match PathSpecifier unknown type %s", reflect.TypeOf(rule.Match.PathSpecifier).String())
			}
			if prefixFound || pathFound || regexFound {
				for _, header := range rule.Match.Headers {
					if header.Name == ":authority" && header.HeaderMatchSpecifier.(*route.HeaderMatcher_ExactMatch).ExactMatch == params.Conditions.Hostname {
						domainFound = true
					}
				}
				if len(params.Conditions.Methods) > 0 {
					for _, v1 := range rule.Match.Headers {
						for _, v2 := range params.Conditions.Methods {
							if v1.GetName() == ":method" && v1.GetExactMatch() == v2 {
								methodsFound[v2] = true
							}
						}
					}
				}
				if domainFound && len(methodsFound) == len(params.Conditions.Methods) {
					matchedEntries++
				}
			}
		}
		logger.Debugf("matched entries: %d", matchedEntries)

		if matchedEntries > 1 {
			return fmt.Errorf("Duplicate entry found")
		}

		if params.Conditions.Path == "" && !prefixFound {
			return fmt.Errorf("JWT: prefix not found")
		}
		if params.Conditions.Path != "" && !pathFound {
			return fmt.Errorf("JWT: path not found")
		}
		if params.Conditions.Hostname != "" && !domainFound {
			return fmt.Errorf("JWT: domain not found")
		}
		if len(params.Conditions.Methods) > 0 {
			for _, v := range params.Conditions.Methods {
				if _, ok := methodsFound[v]; !ok {
					return fmt.Errorf("JWT: Methods not found: %s (expected %s)", v, strings.Join(params.Conditions.Methods, ","))
				}
			}
		}

		logger.Debugf("Prefix, path, methods & domain found")
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

func validateAuthz(listeners []cacheTypes.Resource, params ListenerParams) error {
	if len(listeners) == 0 {
		return fmt.Errorf("Listener is empty (got %d)", len(listeners))
	}

	for _, cachedListenerResource := range listeners {
		cachedListener := cachedListenerResource.(*api.Listener)

		if cachedListener.Name == "l_http" {
			manager, err := getListenerHTTPConnectionManager(cachedListener)
			if err != nil {
				return err
			}
			authzConfig, err := getListenerHTTPFilterAuthz(manager.HttpFilters)
			if err != nil {
				return err
			}
			err = validateAuthzConfig(authzConfig, params, cachedListener.Name)
		} else if cachedListener.Name == "l_tls" {
			for _, filterChain := range cachedListener.FilterChains {
				if len(filterChain.Filters) == 0 {
					return fmt.Errorf("No filters found in listener %s", cachedListener.Name)
				}
				manager, err := getManager((filterChain.Filters[getFilterIndexByName(filterChain.Filters, Envoy_HTTP_Filter)].ConfigType).(*api.Filter_TypedConfig))
				if err != nil {
					return fmt.Errorf("Could not extract manager from listener %s", cachedListener.Name)
				}
				authzConfig, err := getListenerHTTPFilterAuthz(manager.HttpFilters)
				if err != nil {
					return err
				}
				err = validateAuthzConfig(authzConfig, params, cachedListener.Name)
			}
		} else {
			return fmt.Errorf("Unknown listener %s", cachedListener.Name)
		}
	}

	return nil
}

func validateNewHTTPRouterFilter(httpFilter []*hcm.HttpFilter, params ListenerParams) error {
	authzConfig, err := getListenerHTTPFilterAuthz(httpFilter)
	if err != nil {
		return err
	}
	validateAuthzConfig(authzConfig, params, "newHTTPRouterFilter")
	return nil
}
func validateAuthzConfig(authzConfig *extAuthz.ExtAuthz, params ListenerParams, listenerName string) error {
	if authzConfig.FailureModeAllow != params.Authz.FailureModeAllow {
		return fmt.Errorf("Failuremode allow is not correct")
	}
	if authzConfig.GetGrpcService().GetEnvoyGrpc().GetClusterName() != params.Name {
		return fmt.Errorf("authz has wrong cluster")
	}
	timeout, err := time.ParseDuration(params.Authz.Timeout)
	if err != nil {
		return fmt.Errorf("Could not parse timeout %s for listener %s", params.Authz.Timeout, listenerName)
	}
	if !types.DurationProto(timeout).Equal(authzConfig.GetGrpcService().GetTimeout()) {
		return fmt.Errorf("authz has wrong timeout for listener %s", listenerName)
	}

	logger.Debugf("Validated authz filter for listener %s", listenerName)

	return nil
}

func TestRegexMatcher(t *testing.T) {
	a := &matcher.RegexMatcher{
		Regex: "/a.*/",
	}
	b := &matcher.RegexMatcher{
		Regex: "/a.*/",
	}
	c := &matcher.RegexMatcher{
		Regex: "",
	}
	if !regexMatchEqual(a, b) {
		t.Error("regex didn't match but should (a, b)")
		return
	}
	if regexMatchEqual(b, c) {
		t.Error("regex match but should (b, c)")
		return
	}

	return
}

func TestPrefixChangeResultsInAddingNewRoute(t *testing.T) {
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
		RegexRewrite: RegexRewrite{
			Regex:        "abc",
			Substitution: "xyz",
		},
	}
	params2 := ListenerParams{
		Name:           "test_2",
		Protocol:       "http",
		TargetHostname: "www.test2.inv",
		Conditions: Conditions{
			Hostname: "hostname2.example.com",
			Prefix:   "/test2",
		},
		RegexRewrite: RegexRewrite{
			Regex:        "abc2",
			Substitution: "xyz2",
		},
	}
	params3 := ListenerParams{
		Name:           "test_2",
		Protocol:       "http",
		TargetHostname: "www.test2.inv",
		Conditions: Conditions{
			Hostname: "hostname2.example.com",
			Prefix:   "/test2",
		},
		RegexRewrite: RegexRewrite{
			Regex:        "abc3",
			Substitution: "xyz3",
		},
	}
	paramsTLS1 := TLSParams{}

	// create first domain
	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)
	// update listener with new prefix
	if err := l.updateListener(&cache, params2, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	if err := l.updateListener(&cache, params3, paramsTLS1); err != nil {
		t.Errorf("Error: %s", err)
		return
	}
	cachedListener := cache.listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		t.Errorf("Expected l_http (got %s)", cachedListener.Name)
		return
	}

	manager, err := getListenerHTTPConnectionManager(cachedListener)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	routeSpecifier, err := getListenerRouteSpecifier(manager)
	if err != nil {
		t.Errorf("Error: %s", err)
		return
	}

	domainFound := false

	for _, virtualhost := range routeSpecifier.RouteConfig.VirtualHosts {
		for _, domain := range virtualhost.Domains {
			if domain == params2.Conditions.Hostname {
				domainFound = true
				if len(virtualhost.Routes) != 1 {
					t.Errorf("Expected to only have 1 route %+v", virtualhost.Routes)
					return
				}
				if virtualhost.Routes[0].Action.(*route.Route_Route).Route.RegexRewrite.Pattern.Regex != "abc3" {
					t.Errorf("wrong regex pattern: %s", virtualhost.Routes[0].Action.(*route.Route_Route).Route.RegexRewrite.Pattern.Regex)
					return
				}
				if virtualhost.Routes[0].Action.(*route.Route_Route).Route.RegexRewrite.Substitution != "xyz3" {
					t.Errorf("wrong substitution pattern: %s", virtualhost.Routes[0].Action.(*route.Route_Route).Route.RegexRewrite.Substitution)
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
