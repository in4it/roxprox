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
func (l *Listener) updateListenerWithNewCert(cache *WorkQueueCache, params TLSParams) error {
	var listenerFound bool
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if ll.Name == "l_tls" {
			listenerFound = true
			logger.Debugf("Matching listener found, updating: %s", ll.Name)
			// add cert and key to tls listener
			ll.FilterChains = append(ll.FilterChains, listener.FilterChain{
				FilterChainMatch: &listener.FilterChainMatch{
					// TODO (params.Domainname)
					ServerNames: []string{params.Name},
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
			})
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
			logger.Debugf("Created new typedConfig: %+v", cache.listeners[listenerKey])
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
	if len(ll.FilterChains) == 0 {
		return manager, fmt.Errorf("No filterchains found in listener %s", ll.Name)
	}
	if len(ll.FilterChains[0].Filters) == 0 {
		return manager, fmt.Errorf("No filters found in listener %s", ll.Name)
	}
	typedConfig := (ll.FilterChains[0].Filters[0].ConfigType).(*listener.Filter_TypedConfig)
	err := types.UnmarshalAny(typedConfig.TypedConfig, &manager)
	if err != nil {
		return manager, err
	}
	return manager, nil
}
func (l *Listener) getListenerHTTPConnectionManagerTLS(ll *api.Listener, hostname string) (hcm.HttpConnectionManager, error) {
	var manager hcm.HttpConnectionManager

	filterId := -1

	for _, filter := range ll.FilterChains {
		for k, serverName := range filter.FilterChainMatch.ServerNames {
			if serverName == hostname {
				filterId = k
			}
		}
	}
	if filterId == -1 {
		return manager, fmt.Errorf(Error_NoFilterFound)
	} else {
		if len(ll.FilterChains[filterId].Filters) == 0 {
			return manager, fmt.Errorf("No filters found in listener %s", ll.Name)
		}
		typedConfig := (ll.FilterChains[filterId].Filters[0].ConfigType).(*listener.Filter_TypedConfig)
		err := types.UnmarshalAny(typedConfig.TypedConfig, &manager)
		if err != nil {
			return manager, err
		}
	}

	return manager, nil
}
func (l *Listener) getVirtualHost(hostname, targetHostname, targetPrefix, clusterName, virtualHostName string, methods []string) route.VirtualHost {
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

	if len(methods) > 0 {
		var headers []*route.HeaderMatcher
		for _, method := range methods {
			headers = append(headers, &route.HeaderMatcher{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
					ExactMatch: method,
				},
			})
		}
		match = route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: targetPrefix,
			},
			Headers: headers,
		}
	} else {
		match = route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: targetPrefix,
			},
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

func (l *Listener) getJwtRule(conditions Conditions, clusterName string, jwtProvider string) *jwtAuth.RequirementRule {
	var match *route.RouteMatch
	prefix := "/"
	if conditions.Prefix != "" {
		prefix = conditions.Prefix
	}

	if conditions.Hostname == "" {
		match = &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Path{
				Path: prefix,
			},
		}
	} else {
		match = &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Path{
				Path: prefix,
			},
			Headers: []*route.HeaderMatcher{
				{
					Name: ":authority",
					HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
						ExactMatch: conditions.Hostname,
					},
				},
			},
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

func (l *Listener) updateListener(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	var listenerKey = -1

	tls, targetPrefix, virtualHostname, listenerName, _ := l.getListenerAttributes(params, paramsTLS)

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
		if err != nil {
			return err
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
	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostname, params.Conditions.Methods)

	// check if we need to overwrite the virtualhost
	virtualHostKey := -1
	for k, curVirtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
		if v.Name == curVirtualHost.Name {
			virtualHostKey = k
			logger.Debugf("Found existing virtualhost with name %s", v.Name)
		}
	}

	if virtualHostKey >= 0 {
		// append new routes to existing virtualhost
		logger.Debugf("Adding new routes to %s", v.Name)
		routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes = append(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, v.Routes...)
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
		jwtConfig.Rules = append(jwtConfig.Rules, l.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider))
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
	}

	manager.RouteSpecifier = routeSpecifier
	pbst, err := types.MarshalAny(&manager)
	if err != nil {
		panic(err)
	}
	ll.FilterChains[0].Filters[0].ConfigType = &listener.Filter_TypedConfig{
		TypedConfig: pbst,
	}
	logger.Debugf("Updated listener with new Virtualhost")

	return nil
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

func (l *Listener) getListenerAttributes(params ListenerParams, paramsTLS TLSParams) (bool, string, string, string, uint32) {
	var (
		tls             bool
		listenerName    string
		targetPrefix    = "/"
		virtualHostName string
		listenerPort    uint32
	)

	if paramsTLS.CertBundle != "" {
		tls = true
	}

	if params.Conditions.Prefix != "" && params.Conditions.Prefix != "/" {
		targetPrefix = params.Conditions.Prefix
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
	return tls, targetPrefix, virtualHostName, listenerName, listenerPort
}

func (l *Listener) findListener(listeners []cache.Resource, params ListenerParams) (int, error) {
	for k, v := range listeners {
		if v.(*api.Listener).Name == "l_"+params.Name {
			return k, nil
		}
	}
	return -1, fmt.Errorf("Cluster not found")
}
func (l *Listener) findTLSListener(listeners []cache.Resource, params ListenerParams) (int, error) {
	for k, v := range listeners {
		if v.(*api.Listener).Name == "l_"+params.Name+"_tls" {
			return k, nil
		}
	}
	return -1, fmt.Errorf("Cluster not found")
}
func (l *Listener) createListener(params ListenerParams, paramsTLS TLSParams) *api.Listener {
	var err error

	tls, targetPrefix, virtualHostName, listenerName, listenerPort := l.getListenerAttributes(params, paramsTLS)

	logger.Debugf("Processing params %+v", params)
	logger.Infof("Creating listener " + listenerName)

	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostName, params.Conditions.Methods)
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
		jwtConfig.Rules = append(jwtConfig.Rules, l.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider))
	}
	jwtAuth, err := types.MarshalAny(jwtConfig)
	if err != nil {
		panic(err)
	}

	httpFilters := []*hcm.HttpFilter{
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

	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.AUTO,
		StatPrefix: "ingress_http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &api.RouteConfiguration{
				Name:         strings.Replace(listenerName, "l_", "r_", 1),
				VirtualHosts: virtualHosts,
			},
		},
		HttpFilters: httpFilters,
	}

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

func (c *Listener) GetListenerNames(listeners []cache.Resource) []string {
	var listenerNames []string
	for _, v := range listeners {
		listenerNames = append(listenerNames, v.(*api.Listener).Name)
	}
	return listenerNames
}
