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
		if ll.Name == "l_"+params.Name+"_tls" {
			listenerFound = true
			logger.Debugf("Matching listener found, updating: %s", ll.Name)
			// add cert and key to tls listener
			ll.FilterChains[0].TlsContext = &auth.DownstreamTlsContext{
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
		if ll.Name == "l_"+clusterName {
			logger.Debugf("Matching listener found, updating: %s", ll.Name)
			manager, err := l.getListenerHTTPConnectionManager(ll)
			if err != nil {
				return err
			}
			routeSpecifier, err := l.getListenerRouteSpecifier(manager)
			if err != nil {
				return err
			}
			for k, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
				if virtualHost.Name == clusterName+"_service" {
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
func (l *Listener) getVirtualHost(hostname, targetHostname, targetPrefix, clusterName, virtualHostName string) route.VirtualHost {
	return route.VirtualHost{
		Name:    virtualHostName,
		Domains: []string{hostname},

		//TypedPerFilterConfig: filterConfig,

		Routes: []route.Route{{
			Match: route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: targetPrefix,
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					HostRewriteSpecifier: &route.RouteAction_HostRewrite{
						HostRewrite: targetHostname,
					},
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: clusterName,
					},
				},
			},
		}}}
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
func (l *Listener) getJwtRules(virtualHosts []route.VirtualHost) []*jwtAuth.RequirementRule {
	jwtAuthRules := []*jwtAuth.RequirementRule{}
	for _, v := range virtualHosts {
		if strings.Contains(v.Name, "jwt:") {
			var (
				jwtProvider string
				match       *route.RouteMatch
			)
			nameAttrs := strings.Split(v.Name, "_")

			if len(nameAttrs) > 3 {

				for _, vv := range v.Routes {

					for _, attr := range nameAttrs {
						if strings.HasPrefix(attr, "jwt:") {
							jwtProvider = attr[4:]
						}
					}

					if nameAttrs[2] == "wildcard" {
						match = &route.RouteMatch{
							PathSpecifier: vv.Match.PathSpecifier,
						}
					} else {
						match = &route.RouteMatch{
							PathSpecifier: vv.Match.PathSpecifier,
							Headers: []*route.HeaderMatcher{
								{
									Name: ":authority",
									HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
										ExactMatch: nameAttrs[2],
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
					jwtAuthRules = append(jwtAuthRules, rule)
				}
			}
		}
	}

	return jwtAuthRules
}

func (l *Listener) updateListener(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	var listenerKey = -1

	_, targetPrefix, virtualHostname, _, listenerName, _ := l.getListenerAttributes(params, paramsTLS)

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
	ll := cache.listeners[listenerKey].(*api.Listener)
	manager, err := l.getListenerHTTPConnectionManager(ll)
	if err != nil {
		return err
	}
	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		return err
	}

	// create new virtualhost
	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostname)

	// check if we need to overwrite the virtualhost
	virtualHostKey := -1
	for k, curVirtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
		if v.Name == curVirtualHost.Name {
			virtualHostKey = k
			logger.Debugf("Found existing virtualhost with name %s", v.Name)
		}
	}

	if virtualHostKey >= 0 {
		routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey] = v
	} else {
		// check if there's not already a virtualhost with this domain
		domainAlreadyExists := false
		for _, curVirtualHosts := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, domain := range curVirtualHosts.Domains {
				if domain == params.Conditions.Hostname {
					domainAlreadyExists = true
				}
			}
		}
		if domainAlreadyExists {
			return fmt.Errorf("Cannot add virtualhost, domain already exists")
		}
		// append new virtualhost
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
		jwtConfig.Rules = l.getJwtRules(routeSpecifier.RouteConfig.VirtualHosts)
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

func (l *Listener) getListenerAttributes(params ListenerParams, paramsTLS TLSParams) (bool, string, string, string, string, uint32) {
	var (
		tls             bool
		listenerName    string
		targetPrefix    = "/"
		virtualHostName string
		routeConfigName string
		listenerPort    uint32
	)

	if paramsTLS.CertBundle != "" {
		tls = true
	}

	if params.Conditions.Prefix != "" && params.Conditions.Prefix != "/" {
		targetPrefix = params.Conditions.Prefix
	}

	if params.Conditions.Hostname == "" {
		virtualHostName = params.Name + "_service" + "_wildcard"
		routeConfigName = params.Name + "_route" + "_wildcard"
	} else {
		virtualHostName = params.Name + "_service" + "_" + params.Conditions.Hostname
		routeConfigName = params.Name + "_route" + "_" + params.Conditions.Hostname
	}

	if params.Auth.JwtProvider != "" {
		virtualHostName += "_jwt:" + params.Auth.JwtProvider
	}

	if tls {
		listenerPort = 10001
		listenerName = "l_tls"
		virtualHostName = virtualHostName + "_tls"
		routeConfigName = routeConfigName + "_tls"
	} else {
		listenerPort = 10000
		listenerName = "l_http"
	}
	return tls, targetPrefix, virtualHostName, routeConfigName, listenerName, listenerPort
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

	tls, targetPrefix, virtualHostName, routeConfigName, listenerName, listenerPort := l.getListenerAttributes(params, paramsTLS)

	logger.Infof("Creating listener " + listenerName)

	v := l.getVirtualHost(params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostName)

	jwtConfig := l.getJwtConfig(params.Auth)
	jwtConfig.Rules = l.getJwtRules([]route.VirtualHost{v})
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
				Name:         routeConfigName,
				VirtualHosts: []route.VirtualHost{v},
			},
		},
		HttpFilters: httpFilters,
	}

	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	listener := &api.Listener{
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
		// add cert and key to tls listener
		listener.FilterChains[0].TlsContext = &auth.DownstreamTlsContext{
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
	return listener
}

func (c *Listener) GetListenerNames(listeners []cache.Resource) []string {
	var listenerNames []string
	for _, v := range listeners {
		listenerNames = append(listenerNames, v.(*api.Listener).Name)
	}
	return listenerNames
}
