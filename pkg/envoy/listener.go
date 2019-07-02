package envoy

import (
	"fmt"
	"strings"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	jwtAuth "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/jwt_authn/v2alpha"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/gogo/protobuf/types"
)

const Error_NoFilterChainFound = "NoFilterChainFound"
const Error_NoFilterFound = "NoFilterFound"

type Listener struct{}

func newListener() *Listener {
	return &Listener{}
}
func (l *Listener) updateListenerWithJwtProvider(cache *WorkQueueCache, params ListenerParams) error {
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		manager, err := l.getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
		// add routes to jwtProvider
		jwtConfig, err := l.getListenerHTTPFilter(manager.HttpFilters)
		if err != nil {
			return err
		}
		if jwtConfig.Providers == nil {
			jwtConfig.Providers = make(map[string]*jwtAuth.JwtProvider)
		}
		jwtNewConfig := l.getJwtConfig(params.Auth)
		jwtConfig.Providers[params.Auth.JwtProvider] = jwtNewConfig.Providers[params.Auth.JwtProvider]
		logger.Debugf("Adding/updating %s to jwt config", params.Auth.JwtProvider)

		jwtConfigEncoded, err := types.MarshalAny(&jwtConfig)
		if err != nil {
			panic(err)
		}

		manager.HttpFilters = []*hcm.HttpFilter{
			{
				Name: "envoy.filters.http.jwt_authn",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: jwtConfigEncoded,
				},
			},
			{
				Name: util.Router,
			},
		}
		pbst, err := types.MarshalAny(&manager)
		if err != nil {
			panic(err)
		}
		ll.FilterChains[0].Filters[0].ConfigType = &listener.Filter_TypedConfig{
			TypedConfig: pbst,
		}
	}
	return nil
}
func (l *Listener) newTLSFilterChain(params TLSParams) listener.FilterChain {
	return listener.FilterChain{
		FilterChainMatch: &listener.FilterChainMatch{
			ServerNames: []string{params.Domain},
		},
		TlsContext: &auth.DownstreamTlsContext{
			CommonTlsContext: &auth.CommonTlsContext{
				TlsCertificates: []*auth.TlsCertificate{
					{
						CertificateChain: &core.DataSource{
							Specifier: &core.DataSource_InlineString{
								InlineString: params.CertBundle,
							},
						},
						PrivateKey: &core.DataSource{
							Specifier: &core.DataSource_InlineString{
								InlineString: params.PrivateKey,
							},
						},
					},
				},
			},
		},
	}
}
func (l *Listener) updateListenerWithNewCert(cache *WorkQueueCache, params TLSParams) error {
	var listenerFound bool
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if ll.Name == "l_tls" {
			listenerFound = true
			filterId := l.getFilterChainId(ll.FilterChains, params.Domain)
			if filterId == -1 {
				logger.Debugf("Updating %s with new filter and certificate for domain %s", ll.Name, params.Domain)
				ll.FilterChains = append(ll.FilterChains, l.newTLSFilterChain(params))
			} else {
				logger.Debugf("Updating existing filterchain in %s with certificate for domain %s", ll.Name, params.Domain)
				filterChain := l.newTLSFilterChain(params)
				ll.FilterChains[filterId].TlsContext = filterChain.TlsContext
			}
		}
	}
	if !listenerFound {
		return fmt.Errorf("No tls listener found")
	}
	return nil
}

func (l *Listener) updateListenerWithChallenge(cache *WorkQueueCache, challenge ChallengeParams) error {
	clusterName := challenge.Name
	logger.Debugf("Update listener with challenge for: %s", clusterName)
	newRoute := []route.Route{
		{
			Match: route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Path{
					Path: "/.well-known/acme-challenge/" + challenge.Token,
				},
			},
			Action: &route.Route_DirectResponse{
				DirectResponse: &route.DirectResponseAction{
					Status: 200,
					Body: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: challenge.Body,
						},
					},
				},
			},
		},
	}
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if ll.Name == "l_http" {
			logger.Debugf("Matching listener found, updating: %s", ll.Name)
			manager, err := l.getListenerHTTPConnectionManager(ll)
			if err != nil {
				return err
			}
			routeSpecifier, err := l.getListenerRouteSpecifier(manager)
			if err != nil {
				return err
			}
			// TODO: check whether virtualhost exists for *, or add new
			for k, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
				if virtualHost.Name == "v_nodomain" {
					routeSpecifier.RouteConfig.VirtualHosts[k].Routes = append(newRoute, routeSpecifier.RouteConfig.VirtualHosts[k].Routes...)
				}
			}
			manager.RouteSpecifier = routeSpecifier
			pbst, err := types.MarshalAny(&manager)
			if err != nil {
				panic(err)
			}
			ll.FilterChains[0].Filters[0].ConfigType = &listener.Filter_TypedConfig{
				TypedConfig: pbst,
			}
		}
	}
	return nil
}
func (l *Listener) getListenerRouteSpecifier(manager hcm.HttpConnectionManager) (*hcm.HttpConnectionManager_RouteConfig, error) {
	var routeSpecifier *hcm.HttpConnectionManager_RouteConfig
	routeSpecifier = manager.RouteSpecifier.(*hcm.HttpConnectionManager_RouteConfig)
	if len(routeSpecifier.RouteConfig.VirtualHosts) == 0 {
		return routeSpecifier, fmt.Errorf("No virtualhosts found in routeconfig")
	}
	return routeSpecifier, nil
}
func (l *Listener) getListenerHTTPConnectionManager(ll *api.Listener) (hcm.HttpConnectionManager, error) {
	var manager hcm.HttpConnectionManager
	var err error
	if len(ll.FilterChains) == 0 {
		return manager, fmt.Errorf("No filterchains found in listener %s", ll.Name)
	}
	if len(ll.FilterChains[0].Filters) == 0 {
		return manager, fmt.Errorf("No filters found in listener %s", ll.Name)
	}
	manager, err = l.getManager((ll.FilterChains[0].Filters[0].ConfigType).(*listener.Filter_TypedConfig))
	if err != nil {
		return manager, err
	}
	return manager, nil
}
func (l *Listener) getFilterChainId(filterChains []listener.FilterChain, hostname string) int {
	filterId := -1

	for k, filter := range filterChains {
		for _, serverName := range filter.FilterChainMatch.ServerNames {
			if serverName == hostname {
				filterId = k
			}
		}
	}
	return filterId
}
func (l *Listener) getListenerHTTPConnectionManagerTLS(ll *api.Listener, hostname string) (hcm.HttpConnectionManager, error) {
	var err error
	var manager hcm.HttpConnectionManager

	filterId := l.getFilterChainId(ll.FilterChains, hostname)

	if filterId == -1 {
		return manager, fmt.Errorf(Error_NoFilterChainFound)
	} else {
		if len(ll.FilterChains[filterId].Filters) == 0 {
			return manager, fmt.Errorf(Error_NoFilterFound)
		}
		manager, err = l.getManager(ll.FilterChains[filterId].Filters[0].ConfigType.(*listener.Filter_TypedConfig))
		if err != nil {
			return manager, err
		}
	}

	return manager, nil
}
func (l *Listener) getManager(typedConfig *listener.Filter_TypedConfig) (hcm.HttpConnectionManager, error) {
	var manager hcm.HttpConnectionManager

	err := types.UnmarshalAny(typedConfig.TypedConfig, &manager)
	if err != nil {
		return manager, err
	}

	return manager, nil
}
func (l *Listener) getVirtualHost(hostname, targetHostname, targetPrefix, clusterName, virtualHostName string, methods []string, matchType string) route.VirtualHost {
	var hostRewriteSpecifier *route.RouteAction_HostRewrite
	var match route.RouteMatch

	if hostname == "" {
		hostname = "*"
	}

	if targetHostname != "" {
		hostRewriteSpecifier = &route.RouteAction_HostRewrite{
			HostRewrite: targetHostname,
		}
	}

	var headers []*route.HeaderMatcher
	if len(methods) > 0 {
		for _, method := range methods {
			headers = append(headers, &route.HeaderMatcher{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
					ExactMatch: method,
				},
			})
		}
	}
	if matchType == "prefix" {
		match = route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: targetPrefix,
			},
			Headers: headers,
		}
	} else if matchType == "path" {
		match = route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Path{
				Path: targetPrefix,
			},
			Headers: headers,
		}
	}

	routes := []route.Route{
		{
			Match: match,
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					HostRewriteSpecifier: hostRewriteSpecifier,
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: clusterName,
					},
				},
			},
		},
	}

	return route.VirtualHost{
		Name:    virtualHostName,
		Domains: []string{hostname},

		Routes: routes,
	}
}
func (l *Listener) getJwtConfig(auth Auth) *jwtAuth.JwtAuthentication {
	if auth.JwtProvider == "" {
		return &jwtAuth.JwtAuthentication{
			Providers: map[string]*jwtAuth.JwtProvider{},
		}
	}
	return &jwtAuth.JwtAuthentication{
		Providers: map[string]*jwtAuth.JwtProvider{
			auth.JwtProvider: &jwtAuth.JwtProvider{
				Issuer:  auth.Issuer,
				Forward: auth.Forward,
				JwksSourceSpecifier: &jwtAuth.JwtProvider_RemoteJwks{
					RemoteJwks: &jwtAuth.RemoteJwks{
						HttpUri: &core.HttpUri{
							Uri: auth.RemoteJwks,
							HttpUpstreamType: &core.HttpUri_Cluster{
								Cluster: "jwtProvider_" + auth.JwtProvider,
							},
						},
					},
				},
			},
		},
	}
}

func (l *Listener) getJwtRule(conditions Conditions, clusterName string, jwtProvider string, matchType string) *jwtAuth.RequirementRule {
	var match *route.RouteMatch
	prefix := "/"
	if conditions.Prefix != "" {
		prefix = conditions.Prefix
	}
	var headers []*route.HeaderMatcher
	if conditions.Hostname != "" {
		headers = append(headers, &route.HeaderMatcher{
			Name: ":authority",
			HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
				ExactMatch: conditions.Hostname,
			},
		})
	}
	if len(conditions.Methods) > 0 {
		for _, method := range conditions.Methods {
			headers = append(headers, &route.HeaderMatcher{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
					ExactMatch: method,
				},
			})
		}
	}
	if matchType == "prefix" {
		match = &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: prefix,
			},
			Headers: headers,
		}
	} else if matchType == "path" {
		match = &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Path{
				Path: conditions.Path,
			},
			Headers: headers,
		}
	}
	rule := &jwtAuth.RequirementRule{
		Match: match,
		Requires: &jwtAuth.JwtRequirement{
			RequiresType: &jwtAuth.JwtRequirement_ProviderName{
				ProviderName: jwtProvider,
			},
		},
	}

	return rule
}

func (l *Listener) newTLSFilter(params ListenerParams, paramsTLS TLSParams, listenerName string) []listener.Filter {
	// get empty jwt config
	jwtConfig := l.getJwtConfig(params.Auth)
	jwtConfigEncoded, err := types.MarshalAny(jwtConfig)
	if err != nil {
		panic(err)
	}
	httpFilters := l.newHttpFilter(jwtConfigEncoded)
	newEmptyVirtualHost := route.VirtualHost{
		Name:    "v_" + params.Conditions.Hostname,
		Domains: []string{params.Conditions.Hostname},
		Routes:  []route.Route{},
	}
	manager := l.newManager(strings.Replace(listenerName, "l_", "r_", 1), []route.VirtualHost{newEmptyVirtualHost}, httpFilters)
	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}
	return []listener.Filter{{
		Name: util.HTTPConnectionManager,
		ConfigType: &listener.Filter_TypedConfig{
			TypedConfig: pbst,
		},
	}}
}

func (l *Listener) updateListener(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	var listenerKey = -1

	tls, targetPrefix, virtualHostname, listenerName, _, matchType := l.getListenerAttributes(params, paramsTLS)

	logger.Infof("Updating listener " + listenerName)

	for k, listener := range cache.listeners {
		if (listener.(*api.Listener)).Name == listenerName {
			listenerKey = k
		}
	}
	if listenerKey == -1 {
		return fmt.Errorf("No matching listener found")
	}

	// update listener
	var manager hcm.HttpConnectionManager
	var err error

	ll := cache.listeners[listenerKey].(*api.Listener)
	if tls {
		manager, err = l.getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
		if err.Error() == Error_NoFilterChainFound {
			// create newFilterChain with new empty Filter
			newFilterChain := l.newTLSFilterChain(paramsTLS)
			newFilterChain.Filters = l.newTLSFilter(params, paramsTLS, listenerName)
			ll.FilterChains = append(ll.FilterChains, newFilterChain)
			manager, err = l.getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
			if err != nil {
				return fmt.Errorf("Created new filter chain, but still error: %s", err)
			}
		} else if err.Error() == Error_NoFilterFound {
			filterId := l.getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
			ll.FilterChains[filterId].Filters = l.newTLSFilter(params, paramsTLS, listenerName)
			manager, err = l.getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
			if err != nil {
				return fmt.Errorf("Created new filter, but still error: %s", err)
			}
		}
	} else {
		manager, err = l.getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
	}

	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		return err
	}

	// create new virtualhost
	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostname, params.Conditions.Methods, matchType)

	// check if we need to overwrite the virtualhost
	virtualHostKey := -1
	for k, curVirtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
		if v.Name == curVirtualHost.Name {
			virtualHostKey = k
			logger.Debugf("Found existing virtualhost with name %s", v.Name)
		}
	}

	if virtualHostKey >= 0 {
		if len(v.Routes) != 1 {
			return fmt.Errorf("Routes containes more than 1 route (contains %d elements)", len(v.Routes))
		}
		if l.routeExist(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, v.Routes[0]) {
			logger.Debugf("Route already exists, not adding route for %s", v.Name)
		} else {
			// append new routes to existing virtualhost
			logger.Debugf("Adding new routes to %s", v.Name)
			routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes = append(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, v.Routes[0])
		}
	} else {
		routeSpecifier.RouteConfig.VirtualHosts = append(routeSpecifier.RouteConfig.VirtualHosts, v)
	}

	// add routes to jwtProvider
	jwtConfig, err := l.getListenerHTTPFilter(manager.HttpFilters)
	if err != nil {
		return err
	}

	// find provider
	if params.Auth.JwtProvider != "" {
		providerFound := false
		if jwtConfig.Providers == nil {
			jwtConfig.Providers = make(map[string]*jwtAuth.JwtProvider)
		} else {
			for k := range jwtConfig.Providers {
				logger.Debugf("comparing %s with %s", k, params.Auth.JwtProvider)
				if k == params.Auth.JwtProvider {
					providerFound = true
				}
			}
		}

		if !providerFound {
			jwtNewConfig := l.getJwtConfig(params.Auth)
			jwtConfig.Providers[params.Auth.JwtProvider] = jwtNewConfig.Providers[params.Auth.JwtProvider]
			logger.Debugf("adding provider %s to jwt config", params.Auth.JwtProvider)
		}

		// update rules
		jwtConfig.Rules = append(jwtConfig.Rules, l.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider, matchType))
		jwtConfigEncoded, err := types.MarshalAny(&jwtConfig)
		if err != nil {
			panic(err)
		}

		manager.HttpFilters = l.newHttpFilter(jwtConfigEncoded)
	}

	manager.RouteSpecifier = routeSpecifier
	pbst, err := types.MarshalAny(&manager)
	if err != nil {
		panic(err)
	}

	filterId := 0
	if tls {
		// tls has multiple filterChains
		filterId = l.getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
	}
	if len(ll.FilterChains[filterId].Filters) == 0 {
		return fmt.Errorf("Can't modify filterchain: filter does not exist")
	}

	// modify filter
	ll.FilterChains[filterId].Filters[0].ConfigType = &listener.Filter_TypedConfig{
		TypedConfig: pbst,
	}

	logger.Debugf("Updated listener with new Virtualhost")

	return nil
}

func (l *Listener) routeExist(routes []route.Route, route route.Route) bool {
	routeFound := false
	for _, v := range routes {
		if l.cmpMatch(&v.Match, &route.Match) && v.Action.Equal(route.Action) {
			routeFound = true
		}
	}
	return routeFound
}
func (l *Listener) routeIndex(routes []route.Route, route route.Route) int {
	for index, v := range routes {
		if l.cmpMatch(&v.Match, &route.Match) && v.Action.Equal(route.Action) {
			return index
		}
	}
	return -1
}

func (l *Listener) getListenerHTTPFilter(httpFilter []*hcm.HttpFilter) (jwtAuth.JwtAuthentication, error) {
	var jwtConfig jwtAuth.JwtAuthentication
	httpFilterPos := -1
	for k, v := range httpFilter {
		if v.Name == "envoy.filters.http.jwt_authn" {
			httpFilterPos = k
		}
	}
	if httpFilterPos == -1 {
		return jwtConfig, fmt.Errorf("HttpFilter for jwt missing")
	}
	err := types.UnmarshalAny(httpFilter[httpFilterPos].GetTypedConfig(), &jwtConfig)
	if err != nil {
		return jwtConfig, err
	}
	return jwtConfig, nil
}

func (l *Listener) getListenerAttributes(params ListenerParams, paramsTLS TLSParams) (bool, string, string, string, uint32, string) {
	var (
		tls             bool
		listenerName    string
		targetPrefix    string
		matchType       string
		virtualHostName string
		listenerPort    uint32
	)

	if paramsTLS.CertBundle != "" {
		tls = true
	}

	if params.Conditions.Prefix != "" {
		matchType = "prefix"
		targetPrefix = params.Conditions.Prefix
	}
	if params.Conditions.Path != "" {
		matchType = "path"
		targetPrefix = params.Conditions.Path
	}

	if params.Conditions.Prefix == "" && params.Conditions.Path == "" {
		matchType = "prefix"
		targetPrefix = "/"
	}

	if params.Conditions.Hostname == "" {
		virtualHostName = "v_nodomain"
	} else {
		virtualHostName = "v_" + params.Conditions.Hostname
	}

	if tls {
		listenerPort = 10001
		listenerName = "l_tls"
		virtualHostName = virtualHostName + "_tls"
	} else {
		listenerPort = 10000
		listenerName = "l_http"
	}
	return tls, targetPrefix, virtualHostName, listenerName, listenerPort, matchType
}

func (l *Listener) newHttpFilter(jwtAuth *types.Any) []*hcm.HttpFilter {
	return []*hcm.HttpFilter{
		{
			Name: "envoy.filters.http.jwt_authn",
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: jwtAuth,
			},
		},
		{
			Name: util.Router,
		},
	}

}
func (l *Listener) newManager(routeName string, virtualHosts []route.VirtualHost, httpFilters []*hcm.HttpFilter) *hcm.HttpConnectionManager {
	return &hcm.HttpConnectionManager{
		CodecType:  hcm.AUTO,
		StatPrefix: "ingress_http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &api.RouteConfiguration{
				Name:         routeName,
				VirtualHosts: virtualHosts,
			},
		},
		HttpFilters: httpFilters,
	}
}

func (l *Listener) createListener(params ListenerParams, paramsTLS TLSParams) *api.Listener {
	var err error

	tls, targetPrefix, virtualHostName, listenerName, listenerPort, matchType := l.getListenerAttributes(params, paramsTLS)

	logger.Debugf("Processing params %+v", params)
	logger.Infof("Creating listener " + listenerName)

	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostName, params.Conditions.Methods, matchType)
	virtualHosts := []route.VirtualHost{v}

	if virtualHostName != "v_nodomain" && !tls {
		virtualHosts = append(virtualHosts, route.VirtualHost{
			Name:    "v_nodomain",
			Domains: []string{"*"},
			Routes:  []route.Route{},
		})
	}

	jwtConfig := l.getJwtConfig(params.Auth)
	if params.Auth.JwtProvider != "" {
		// add rule if there is a jwtprovider
		jwtConfig.Rules = append(jwtConfig.Rules, l.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider, matchType))
	}
	jwtAuth, err := types.MarshalAny(jwtConfig)
	if err != nil {
		panic(err)
	}

	httpFilters := l.newHttpFilter(jwtAuth)
	manager := l.newManager(strings.Replace(listenerName, "l_", "r_", 1), virtualHosts, httpFilters)

	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	newListener := &api.Listener{
		Name: listenerName,
		Address: core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: listenerPort,
					},
				},
			},
		},
		FilterChains: []listener.FilterChain{{
			Filters: []listener.Filter{{
				Name: util.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
	if tls {
		// this should never happen:
		if params.Conditions.Hostname == "" {
			panic("This should never happen: tls enabled and no hostname set (earlier validation must have failed)")
		}
		newListener.ListenerFilters = []listener.ListenerFilter{
			{
				Name: "envoy.listener.tls_inspector",
			},
		}
		newListener.FilterChains[0].FilterChainMatch = &listener.FilterChainMatch{
			ServerNames: []string{params.Conditions.Hostname},
		}
		// add cert and key to tls listener
		newListener.FilterChains[0].TlsContext = &auth.DownstreamTlsContext{
			CommonTlsContext: &auth.CommonTlsContext{
				TlsCertificates: []*auth.TlsCertificate{
					{
						CertificateChain: &core.DataSource{
							Specifier: &core.DataSource_InlineString{
								InlineString: paramsTLS.CertBundle,
							},
						},
						PrivateKey: &core.DataSource{
							Specifier: &core.DataSource_InlineString{
								InlineString: paramsTLS.PrivateKey,
							},
						},
					},
				},
			},
		}
	}
	return newListener
}

func (l *Listener) GetListenerNames(listeners []cache.Resource) []string {
	var listenerNames []string
	for _, v := range listeners {
		listenerNames = append(listenerNames, v.(*api.Listener).Name)
	}
	return listenerNames
}

func (l *Listener) DeleteRoute(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	listenerKeyHTTP := -1
	listenerKeyTLS := -1
	for k, listener := range cache.listeners {
		if (listener.(*api.Listener)).Name == "l_http" {
			listenerKeyHTTP = k
		} else if (listener.(*api.Listener)).Name == "l_tls" {
			listenerKeyTLS = k
		}
	}

	tls, targetPrefix, virtualHostname, _, _, matchType := l.getListenerAttributes(params, paramsTLS)

	// http listener
	var manager hcm.HttpConnectionManager
	var err error

	var ll *api.Listener
	if tls {
		ll = cache.listeners[listenerKeyTLS].(*api.Listener)
		manager, err = l.getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
	} else {
		ll = cache.listeners[listenerKeyHTTP].(*api.Listener)
		manager, err = l.getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
	}

	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		return err
	}

	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostname, params.Conditions.Methods, matchType)

	virtualHostKey := -1
	for k, curVirtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
		if v.Name == curVirtualHost.Name {
			virtualHostKey = k
			logger.Debugf("Found existing virtualhost with name %s", v.Name)
		}
	}
	if virtualHostKey == -1 {
		return fmt.Errorf("Could not find matching virtualhost")
	}
	if len(v.Routes) != 1 {
		return fmt.Errorf("Expected only 1 route")
	}
	index := l.routeIndex(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, v.Routes[0])
	if index == -1 {
		return fmt.Errorf("Route not found")
	}
	// delete route
	routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes = append(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes[:index], routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes[index+1:]...)
	logger.Debugf("Route deleted")

	if len(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes) == 0 {
		// virtualhost is empty, delete it
		routeSpecifier.RouteConfig.VirtualHosts = append(routeSpecifier.RouteConfig.VirtualHosts[:virtualHostKey], routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey+1:]...)
		logger.Debugf("Virtualhost was empty, deleted")
	}

	// delete jwt rule if necessary
	if params.Auth.JwtProvider != "" {
		jwtConfig, err := l.getListenerHTTPFilter(manager.HttpFilters)
		if err != nil {
			return err
		}
		if _, ok := jwtConfig.Providers[params.Auth.JwtProvider]; ok {
			// update rules
			rule := l.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider, matchType)
			index := l.requirementRuleIndex(jwtConfig.Rules, rule)

			jwtConfig.Rules = append(jwtConfig.Rules[:index], jwtConfig.Rules[index+1:]...)

			jwtConfigEncoded, err := types.MarshalAny(&jwtConfig)
			if err != nil {
				panic(err)
			}

			manager.HttpFilters = l.newHttpFilter(jwtConfigEncoded)
		} else {
			logger.Debugf("Couldn't find jwt provider %s during deleteRoute", params.Auth.JwtProvider)
		}

	}

	manager.RouteSpecifier = routeSpecifier
	pbst, err := types.MarshalAny(&manager)
	if err != nil {
		panic(err)
	}

	filterId := -1
	if tls {
		filterId = l.getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
	} else {
		filterId = 0
	}

	ll.FilterChains[filterId].Filters[0].ConfigType = &listener.Filter_TypedConfig{
		TypedConfig: pbst,
	}

	return nil
}

func (l *Listener) requirementRuleIndex(rules []*jwtAuth.RequirementRule, rule *jwtAuth.RequirementRule) int {
	for index, v := range rules {
		if l.cmpMatch(v.Match, rule.Match) && v.Requires.RequiresType.(*jwtAuth.JwtRequirement_ProviderName).ProviderName == rule.Requires.RequiresType.(*jwtAuth.JwtRequirement_ProviderName).ProviderName {
			return index
		}
	}
	return -1
}

func (l *Listener) cmpMatch(a *route.RouteMatch, b *route.RouteMatch) bool {
	if a.GetPath() != b.GetPath() {
		return false
	}
	if a.GetPrefix() != b.GetPrefix() {
		return false
	}
	aHeaders := a.GetHeaders()
	bHeaders := b.GetHeaders()

	if len(aHeaders) != len(bHeaders) {
		return false
	}
	for k := range aHeaders {
		aa := aHeaders[k]
		bb := bHeaders[k]
		if aa.Name != bb.Name {
			logger.Debugf("mismatch in header name ")
			return false
		}

		if aa.HeaderMatchSpecifier.(*route.HeaderMatcher_ExactMatch).ExactMatch != bb.HeaderMatchSpecifier.(*route.HeaderMatcher_ExactMatch).ExactMatch {
			logger.Debugf("mismatch in header value ")

			return false
		}
	}

	if !a.Equal(b) {
		return false
	}

	return true
}
