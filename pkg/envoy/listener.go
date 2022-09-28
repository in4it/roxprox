package envoy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	alf "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoyType "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	any "github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/anypb"
)

const Error_NoFilterChainFound = "NoFilterChainFound"
const Error_NoFilterFound = "NoFilterFound"
const Envoy_HTTP_Filter = "envoy.filters.network.http_connection_manager"

type listenerDefaultsMapping struct {
	rateLimit       bool
	accessLogConfig bool
	tracing         bool
	authz           bool
	compression     bool
	luaFilter       bool
}

type Listener struct {
	httpFilter                  []*hcm.HttpFilter
	tracing                     *hcm.HttpConnectionManager_Tracing
	accessLoggerConfig          []*alf.AccessLog
	rateLimits                  map[string][]*route.RateLimit
	rateLimitsMapping           map[string]uint
	mTLSListenerDefaultsMapping map[string]listenerDefaultsMapping
}

func newListener() *Listener {
	listener := &Listener{}
	typedRouterConfig, err := anypb.New(&router.Router{})
	if err != nil {
		panic(err)
	}
	listener.httpFilter = []*hcm.HttpFilter{
		{
			Name: "envoy.filters.http.router",
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: typedRouterConfig,
			},
		},
	}
	listener.accessLoggerConfig = []*alf.AccessLog{}
	listener.rateLimits = make(map[string][]*route.RateLimit)
	listener.rateLimitsMapping = make(map[string]uint)
	listener.mTLSListenerDefaultsMapping = make(map[string]listenerDefaultsMapping)

	return listener
}

func (l *Listener) newTLSFilterChain(params TLSParams) *api.FilterChain {
	tlsContext, err := anypb.New(&tls.DownstreamTlsContext{
		CommonTlsContext: &tls.CommonTlsContext{
			TlsCertificates: []*tls.TlsCertificate{
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
	})
	if err != nil {
		panic(err)
	}
	return &api.FilterChain{
		FilterChainMatch: &api.FilterChainMatch{
			ServerNames: []string{params.Domain},
		},
		TransportSocket: &core.TransportSocket{
			Name: "tls",
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: tlsContext,
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
			filterId := getFilterChainId(ll.FilterChains, params.Domain)
			if filterId == -1 {
				logger.Debugf("Updating %s with new filter and certificate for domain %s", ll.Name, params.Domain)
				ll.FilterChains = append(ll.FilterChains, l.newTLSFilterChain(params))
			} else {
				logger.Debugf("Updating existing filterchain in %s with certificate for domain %s", ll.Name, params.Domain)
				filterChain := l.newTLSFilterChain(params)
				ll.FilterChains[filterId].TransportSocket = filterChain.TransportSocket
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
	newRoute := []*route.Route{
		{
			Match: &route.RouteMatch{
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
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				return err
			}
			routeSpecifier, err := getListenerRouteSpecifier(manager)
			if err != nil {
				return err
			}
			routeAdded := false
			for k, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
				if virtualHost.Name == "v_nodomain" {
					routeSpecifier.RouteConfig.VirtualHosts[k].Routes = append(newRoute, routeSpecifier.RouteConfig.VirtualHosts[k].Routes...)
					routeAdded = true
				}
			}
			if !routeAdded {
				// v_nodomain does not exist, add new virtualhost with the new route
				routeSpecifier.RouteConfig.VirtualHosts = append(routeSpecifier.RouteConfig.VirtualHosts, &route.VirtualHost{
					Name:    "v_nodomain",
					Domains: []string{"*"},
					Routes:  newRoute,
				})
			}
			manager.RouteSpecifier = routeSpecifier
			pbst, err := anypb.New(manager)
			if err != nil {
				panic(err)
			}
			ll.FilterChains[0].Filters[getFilterIndexByName(ll.FilterChains[0].Filters, Envoy_HTTP_Filter)].ConfigType = &api.Filter_TypedConfig{
				TypedConfig: pbst,
			}
		}
	}
	return nil
}

func (l *Listener) getVirtualHost(listenerName, hostname, targetHostname, targetPrefix, clusterName, virtualHostName string, methods []string, matchType string, directResponse DirectResponse, enableWebsocket bool, prefixRewrite string, regexRewrite RegexRewrite) *route.VirtualHost {
	var hostRewriteSpecifier *route.RouteAction_HostRewriteLiteral
	var routes []*route.Route
	var routeAction *route.Route_Route
	var upgradeConfigs []*route.RouteAction_UpgradeConfig
	var envoyRegexRewrite *matcher.RegexMatchAndSubstitute
	if hostname == "" {
		hostname = "*"
	}

	if targetHostname != "" {
		hostRewriteSpecifier = &route.RouteAction_HostRewriteLiteral{
			HostRewriteLiteral: targetHostname,
		}
		if enableWebsocket {
			upgradeConfigs = []*route.RouteAction_UpgradeConfig{
				{
					Enabled: &wrappers.BoolValue{
						Value: true,
					},
					UpgradeType: "websocket",
				},
			}
		}
		if regexRewrite.Regex != "" {
			envoyRegexRewrite = &matcher.RegexMatchAndSubstitute{
				Pattern: &matcher.RegexMatcher{
					Regex: regexRewrite.Regex,
				},
				Substitution: regexRewrite.Substitution,
			}
		}
		routeAction = &route.Route_Route{
			Route: &route.RouteAction{
				HostRewriteSpecifier: hostRewriteSpecifier,
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: clusterName,
				},
				UpgradeConfigs: upgradeConfigs,
				PrefixRewrite:  prefixRewrite,
				RegexRewrite:   envoyRegexRewrite,
			},
		}
	} else {
		routeAction = &route.Route_Route{}
	}

	var headers []*route.HeaderMatcher
	if len(methods) > 0 {
		sort.Strings(methods)
		for _, method := range methods {
			headers = append(headers, &route.HeaderMatcher{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{
							Exact: method,
						},
					},
				},
			})
		}
	}
	switch matchType {
	case "prefix":
		if len(headers) == 0 {
			routes = append(routes, &route.Route{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: targetPrefix,
					},
				},
				Action: routeAction,
			})
		} else {
			for _, header := range headers {
				routes = append(routes, &route.Route{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Prefix{
							Prefix: targetPrefix,
						},
						Headers: []*route.HeaderMatcher{header},
					},
					Action: routeAction,
				})
			}
		}
	case "path":
		if len(headers) == 0 {
			routes = append(routes, &route.Route{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Path{
						Path: targetPrefix,
					},
				},
				Action: routeAction,
			})
		} else {
			for _, header := range headers {
				routes = append(routes, &route.Route{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Path{
							Path: targetPrefix,
						},
						Headers: []*route.HeaderMatcher{header},
					},
					Action: routeAction,
				})
			}
		}
	case "regex":
		if len(headers) == 0 {
			routes = append(routes, &route.Route{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_SafeRegex{
						SafeRegex: &matcher.RegexMatcher{
							Regex: targetPrefix,
						},
					},
				},
				Action: routeAction,
			})
		} else {
			for _, header := range headers {
				routes = append(routes, &route.Route{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_SafeRegex{
							SafeRegex: &matcher.RegexMatcher{
								Regex: targetPrefix,
							},
						},
						Headers: []*route.HeaderMatcher{header},
					},
					Action: routeAction,
				})
			}
		}
	}

	// fill out directresponse action if defined
	if directResponse.Status > 0 {
		for routeKey := range routes {
			routes[routeKey].Action = &route.Route_DirectResponse{
				DirectResponse: &route.DirectResponseAction{
					Status: directResponse.Status,
					Body: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: directResponse.Body,
						},
					},
				},
			}
		}
	}

	newVirtualhost := &route.VirtualHost{
		Name:    virtualHostName,
		Domains: []string{hostname},
		Routes:  routes,
	}
	// set ratelimits
	if isDefaultListener(listenerName) || l.HasMTLSDefault(listenerName, "envoy.filters.http.ratelimit") {
		if _, ok := l.rateLimits[listenerName]; ok {
			newVirtualhost.RateLimits = l.rateLimits[listenerName]
		}
	}
	return newVirtualhost
}

func (l *Listener) newTLSFilter(params ListenerParams, paramsTLS TLSParams, listenerName string) []*api.Filter {
	httpFilters := l.newHTTPRouterFilter(listenerName)
	newEmptyVirtualHost := &route.VirtualHost{
		Name:    "v_" + params.Conditions.Hostname,
		Domains: []string{params.Conditions.Hostname},
		Routes:  []*route.Route{},
	}
	manager := l.newManager(listenerName, strings.Replace(listenerName, "l_", "r_", 1), []*route.VirtualHost{newEmptyVirtualHost}, httpFilters, false)
	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}
	return []*api.Filter{{
		Name: wellknown.HTTPConnectionManager,
		ConfigType: &api.Filter_TypedConfig{
			TypedConfig: pbst,
		},
	}}
}

func (l *Listener) updateListener(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	var listenerKey = -1

	tls, targetPrefix, virtualHostname, listenerName, _, matchType := getListenerAttributes(params, paramsTLS)

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
	var manager *hcm.HttpConnectionManager
	var err error

	ll := cache.listeners[listenerKey].(*api.Listener)
	if tls {
		manager, err = getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
		if err != nil && err.Error() == Error_NoFilterChainFound {
			// create newFilterChain with new empty Filter
			newFilterChain := l.newTLSFilterChain(paramsTLS)
			newFilterChain.Filters = l.newTLSFilter(params, paramsTLS, listenerName)
			ll.FilterChains = append(ll.FilterChains, newFilterChain)
			manager, err = getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
			if err != nil {
				return fmt.Errorf("Created new filter chain, but still error: %s", err)
			}
		} else if err != nil && err.Error() == Error_NoFilterFound {
			filterId := getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
			ll.FilterChains[filterId].Filters = l.newTLSFilter(params, paramsTLS, listenerName)
			manager, err = getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
			if err != nil {
				return fmt.Errorf("Created new filter, but still error: %s", err)
			}
		} else if err != nil {
			if err != nil {
				return fmt.Errorf("getListenerHTTPConnectionManagerTLS error: %s", err)
			}
		}
	} else {
		manager, err = getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
	}

	routeSpecifier, err := getListenerRouteSpecifier(manager)
	if err != nil {
		return err
	}

	// create new virtualhost
	v := l.getVirtualHost(ll.Name, params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostname, params.Conditions.Methods, matchType, params.DirectResponse, params.EnableWebSockets, params.PrefixRewrite, params.RegexRewrite)

	// check if we need to overwrite the virtualhost
	virtualHostKey := -1
	for k, curVirtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
		if v.Name == curVirtualHost.Name {
			virtualHostKey = k
		}
	}

	if virtualHostKey >= 0 {
		for _, newRoute := range v.Routes {
			if l.routeExist(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, newRoute) {
				// update route if routeAction is updated
				index := l.routeIndex(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, newRoute)
				if !cmpRoutePrefix(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes[index], newRoute) {
					logger.Debugf("Updating route: rewrite prefix has changed for %s", v.Name)
					routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes[index] = newRoute
				} else {
					logger.Debugf("Route already exists, not adding route for %s", v.Name)
				}
			} else {
				// append new routes to existing virtualhost
				logger.Debugf("Adding new routes to %s", v.Name)
				routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes = append(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, newRoute)
			}
		}
	} else {
		routeSpecifier.RouteConfig.VirtualHosts = append(routeSpecifier.RouteConfig.VirtualHosts, v)
	}

	manager.RouteSpecifier = routeSpecifier
	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}

	filterId := 0
	if tls {
		// tls has multiple filterChains
		filterId = getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
	}
	if len(ll.FilterChains[filterId].Filters) == 0 {
		return fmt.Errorf("Can't modify filterchain: filter does not exist")
	}

	// modify filter
	ll.FilterChains[filterId].Filters[getFilterIndexByName(ll.FilterChains[0].Filters, Envoy_HTTP_Filter)].ConfigType = &api.Filter_TypedConfig{
		TypedConfig: pbst,
	}

	logger.Debugf("Updated listener with new Virtualhost")

	return nil
}

func (l *Listener) routeExist(routes []*route.Route, route *route.Route) bool {
	routeFound := false
	for _, v := range routes {
		if cmpMatch(v.Match, route.Match) && routeActionEqual(v, route) {
			routeFound = true
		}
	}
	return routeFound
}

func (l *Listener) routeIndex(routes []*route.Route, route *route.Route) int {
	for index, v := range routes {
		if cmpMatch(v.Match, route.Match) && routeActionEqual(v, route) {
			return index
		}
	}
	return -1
}

func (l *Listener) newManager(listenerName string, routeName string, virtualHosts []*route.VirtualHost, httpFilters []*hcm.HttpFilter, stripAnyHostPort bool) *hcm.HttpConnectionManager {

	httpConnectionManager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "ingress_http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &route.RouteConfiguration{
				Name:         routeName,
				VirtualHosts: virtualHosts,
			},
		},
		HttpFilters: httpFilters,
	}
	if stripAnyHostPort {
		httpConnectionManager.StripPortMode = &hcm.HttpConnectionManager_StripAnyHostPort{
			StripAnyHostPort: true,
		}
	}
	if isDefaultListener(listenerName) || l.HasMTLSDefault(listenerName, "accessLoggerConfig") {
		httpConnectionManager.AccessLog = l.accessLoggerConfig
	}

	if l.tracing != nil && (isDefaultListener(listenerName) || l.HasMTLSDefault(listenerName, "tracing")) {
		httpConnectionManager.Tracing = l.tracing
	}
	return httpConnectionManager
}

func (l *Listener) createListener(params ListenerParams, paramsTLS TLSParams) *api.Listener {
	var err error

	isTls, _, _, listenerName, listenerPort, _ := getListenerAttributes(params, paramsTLS)

	logger.Infof("Creating listener " + listenerName)

	httpFilters := l.newHTTPRouterFilter(listenerName)
	manager := l.newManager(listenerName, strings.Replace(listenerName, "l_", "r_", 1), []*route.VirtualHost{}, httpFilters, params.Listener.StripAnyHostPort)

	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}

	newListener := &api.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: listenerPort,
					},
				},
			},
		},
		FilterChains: []*api.FilterChain{{
			Filters: []*api.Filter{{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &api.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
	if isTls {
		// this should never happen:
		if params.Conditions.Hostname == "" {
			panic("This should never happen: tls enabled and no hostname set (earlier validation must have failed)")
		}
		newListener.ListenerFilters = []*api.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
			},
		}
		newListener.FilterChains[0].FilterChainMatch = &api.FilterChainMatch{
			ServerNames: []string{params.Conditions.Hostname},
		}
		// add cert and key to tls listener
		tlsContext, err := anypb.New(&tls.DownstreamTlsContext{
			CommonTlsContext: &tls.CommonTlsContext{
				TlsCertificates: []*tls.TlsCertificate{
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
		})
		if err != nil {
			panic(err)
		}
		newListener.FilterChains[0].TransportSocket = &core.TransportSocket{
			Name: "tls",
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: tlsContext,
			},
		}
	}
	return newListener
}

func (l *Listener) GetListenerNames(listeners []cacheTypes.Resource) []string {
	var listenerNames []string
	for _, v := range listeners {
		listenerNames = append(listenerNames, v.(*api.Listener).Name)
	}
	return listenerNames
}

func (l *Listener) DeleteRoute(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	listenerKeyHTTP := -1
	listenerKeyTLS := -1
	listenerKeyMTLS := -1
	for k, listener := range cache.listeners {
		if params.Listener.MTLS != "" && (listener.(*api.Listener)).Name == "l_mtls_"+params.Listener.MTLS {
			listenerKeyMTLS = k
		} else if (listener.(*api.Listener)).Name == "l_http" {
			listenerKeyHTTP = k
		} else if (listener.(*api.Listener)).Name == "l_tls" {
			listenerKeyTLS = k
		}
	}

	tls, targetPrefix, virtualHostname, _, _, matchType := getListenerAttributes(params, paramsTLS)

	// http listener
	var manager *hcm.HttpConnectionManager
	var err error

	var ll *api.Listener
	if params.Listener.MTLS != "" {
		if listenerKeyMTLS == -1 {
			return fmt.Errorf("DeleteRoute: mTLS Listener not found: l_mtls_%s", params.Listener.MTLS)
		}
		ll = cache.listeners[listenerKeyMTLS].(*api.Listener)
		manager, err = getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
	} else if tls {
		ll = cache.listeners[listenerKeyTLS].(*api.Listener)
		manager, err = getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
		if err != nil {
			return err
		}
	} else {
		ll = cache.listeners[listenerKeyHTTP].(*api.Listener)
		manager, err = getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
	}

	routeSpecifier, err := getListenerRouteSpecifier(manager)
	if err != nil {
		return err
	}

	v := l.getVirtualHost(ll.Name, params.Conditions.Hostname, params.TargetHostname, targetPrefix, params.Name, virtualHostname, params.Conditions.Methods, matchType, params.DirectResponse, params.EnableWebSockets, params.PrefixRewrite, params.RegexRewrite)

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
	for _, routeToDelete := range v.Routes {
		index := l.routeIndex(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, routeToDelete)
		if index == -1 {
			return fmt.Errorf("Route not found")
		}
		// delete route
		routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes = append(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes[:index], routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes[index+1:]...)
		logger.Debugf("Route deleted")
	}

	if len(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes) == 0 {
		// virtualhost is empty, delete it
		routeSpecifier.RouteConfig.VirtualHosts = append(routeSpecifier.RouteConfig.VirtualHosts[:virtualHostKey], routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey+1:]...)
		logger.Debugf("Virtualhost was empty, deleted")
	}

	manager.RouteSpecifier = routeSpecifier
	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
	}

	filterId := -1
	if tls {
		filterId = getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
	} else {
		filterId = 0
	}

	ll.FilterChains[filterId].Filters[getFilterIndexByName(ll.FilterChains[0].Filters, Envoy_HTTP_Filter)].ConfigType = &api.Filter_TypedConfig{
		TypedConfig: pbst,
	}

	return nil
}

func (l *Listener) validateListeners(listeners []cacheTypes.Resource, clusterNames []string) (bool, error) {
	logger.Debugf("Validating config...")
	for listenerKey := range listeners {
		ll := listeners[listenerKey].(*api.Listener)

		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			return false, err
		}
		routeSpecifier, err := getListenerRouteSpecifier(manager)
		if err != nil {
			return false, err
		}
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, virtualHostRoute := range virtualHost.Routes {
				if virtualHostRoute.Action != nil {
					switch reflect.TypeOf(virtualHostRoute.Action).String() {
					case "*routev3.Route_Route":
						clusterFound := false
						virtualHostRouteClusterName := virtualHostRoute.Action.(*route.Route_Route).Route.ClusterSpecifier.(*route.RouteAction_Cluster).Cluster
						for _, clusterName := range clusterNames {
							if clusterName == virtualHostRouteClusterName {
								clusterFound = true
							}
						}
						if !clusterFound {
							return false, fmt.Errorf("Cluster not found: %s", virtualHostRouteClusterName)
						}
					case "*routev3.Route_DirectResponse":
						logger.Debugf("Validation: DirectResponse, no cluster validation necessary")
						// no validation necessary
					default:
						return false, fmt.Errorf("Route action type is unknown: %s", reflect.TypeOf(virtualHostRoute.Action).String())
					}
				} else {
					return false, fmt.Errorf("Validation: no route action found for virtualhost: %+v", virtualHost)
				}
			}
		}
	}
	return true, nil
}

func (l *Listener) updateDefaultHTTPRouterFilter(filterName string, filterConfig *any.Any) {
	updateHTTPFilterWithConfig(&l.httpFilter, filterName, filterConfig)
}

func (l *Listener) updateDefaultTracingSetting(tracing TracingParams) {
	tracingConfig := &tracev3.DatadogConfig{
		CollectorCluster: tracing.CollectorCluster,
		ServiceName:      "envoy",
	}
	tracingConfigEncoded, err := anypb.New(tracingConfig)
	if err != nil {
		panic(err)
	}

	l.tracing = &hcm.HttpConnectionManager_Tracing{
		ClientSampling:  &envoyType.Percent{Value: tracing.ClientSampling},
		RandomSampling:  &envoyType.Percent{Value: tracing.RandomSampling},
		OverallSampling: &envoyType.Percent{Value: tracing.OverallSampling},
		Provider: &tracev3.Tracing_Http{
			Name: tracing.ProviderName,
			ConfigType: &tracev3.Tracing_Http_TypedConfig{
				TypedConfig: tracingConfigEncoded,
			},
		},
	}
	// set mTLS listeners defaults
	l.setMTLSDefault(tracing.Listener.MTLS, "tracing")
}

func (l *Listener) updateDefaultCompressionSetting(compressionParams CompressionParams) {
	c := newCompression()
	compressorFilterEncoded, err := c.getCompressionFilterEncoded(compressionParams)
	if err != nil {
		logger.Errorf("Couldn't update default compression filter: %s", err)
		return
	}
	if compressorFilterEncoded == nil {
		return
	}

	updateHTTPFilterWithConfig(&l.httpFilter, "envoy.filters.http.compressor", compressorFilterEncoded)
	// set mTLS listeners defaults
	l.setMTLSDefault(compressionParams.Listener.MTLS, "envoy.filters.http.compressor")

}

func (l *Listener) updateDefaultAccessLogServer(accessLogServerParams AccessLogServerParams) {
	c := newAccessLogServer()
	accessLoggerConfig, err := c.getAccessLoggerConfig(accessLogServerParams)
	if err != nil {
		logger.Errorf("Couldn't get access logger config: %s", err)
		return
	}
	if accessLoggerConfig == nil {
		return
	}

	l.accessLoggerConfig = accessLoggerConfig
	// set mTLS listeners defaults
	l.setMTLSDefault(accessLogServerParams.Listener.MTLS, "accessLoggerConfig")
}

func (l *Listener) updateDefaultAuthzSetting(listenerParams ListenerParams, authzConfig *anypb.Any) {
	l.updateDefaultHTTPRouterFilter("envoy.ext_authz", authzConfig)
	// set mTLS listeners defaults
	l.setMTLSDefault(listenerParams.Listener.MTLS, "envoy.ext_authz")
}

func (l *Listener) updateDefaultRateLimit(rateLimitParams RateLimitParams) {
	r := newRateLimit()

	if !rateLimitParams.Listener.DisableOnDefault {
		if getListenerHTTPFilterIndex("envoy.filters.http.ratelimit", l.httpFilter) == -1 {
			rateLimitConfigEncoded, err := r.getRateLimitConfigEncoded(rateLimitParams)
			if err != nil {
				logger.Errorf("Couldn't update default rateLimit filter: %s", err)
				return
			}
			if rateLimitConfigEncoded == nil {
				return
			}

			updateHTTPFilterWithConfig(&l.httpFilter, "envoy.filters.http.ratelimit", rateLimitConfigEncoded)
		}
	}

	rateLimitVirtualHostConfig, err := r.getRateLimitVirtualHostConfig(rateLimitParams)
	if err != nil {
		logger.Errorf("Couldn't update ratelimit: %s", err)
		return
	}
	if !rateLimitParams.Listener.DisableOnDefault {
		l.updateDefaultRateLimitByListener("l_http", rateLimitParams, rateLimitVirtualHostConfig)
	}
	if rateLimitParams.Listener.MTLS != "" {
		l.updateDefaultRateLimitByListener("l_mtls_"+rateLimitParams.Listener.MTLS, rateLimitParams, rateLimitVirtualHostConfig)
	}

	// set mTLS listeners defaults
	l.setMTLSDefault(rateLimitParams.Listener.MTLS, "envoy.filters.http.ratelimit")
}

func (l *Listener) updateDefaultRateLimitByListener(listenerName string, rateLimitParams RateLimitParams, rateLimitVirtualHostConfig *route.RateLimit) {
	if l.rateLimits[listenerName] == nil {
		l.rateLimits[listenerName] = []*route.RateLimit{}
	}
	if val, ok := l.rateLimitsMapping[listenerName+"#"+rateLimitParams.Name]; ok {
		l.rateLimits[listenerName][val] = rateLimitVirtualHostConfig
	} else {
		l.rateLimits[listenerName] = append(l.rateLimits[listenerName], rateLimitVirtualHostConfig)
	}
	l.rateLimitsMapping[listenerName+"#"+rateLimitParams.Name] = uint(len(l.rateLimits[listenerName]) - 1)
}

func (l *Listener) updateDefaultLuaFilter(luaFilterParams LuaFilterParams) {
	lf := newLuaFilter()
	luaFilterConfigEncoded, err := lf.getLuaFilterConfigEncoded(luaFilterParams)
	if err != nil {
		logger.Errorf("Couldn't get lua filter config: %s", err)
		return
	}
	if luaFilterConfigEncoded == nil {
		return
	}

	updateHTTPFilterWithConfig(&l.httpFilter, "envoy.filters.http.lua", luaFilterConfigEncoded)
	// set mTLS listeners defaults
	if luaFilterParams.Listener.MTLS != "" {
		l.setMTLSDefault(luaFilterParams.Listener.MTLS, "envoy.filters.http.lua")
	}
}

func (l *Listener) newHTTPRouterFilter(listenerName string) []*hcm.HttpFilter {
	httpFilter := []*hcm.HttpFilter{}
	for k := range l.httpFilter {
		if isDefaultListener(listenerName) || l.HasMTLSDefault(listenerName, l.httpFilter[k].Name) {
			httpFilter = append(httpFilter, l.httpFilter[k])
		}
	}
	return httpFilter
}

func (l *Listener) printListener(cache *WorkQueueCache) (string, error) {
	var res string
	for _, listener := range cache.listeners {
		ll := listener.(*api.Listener)
		res += "Listener: " + ll.Name + "\n"
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			return "", err
		}
		routeSpecifier, err := getListenerRouteSpecifier(manager)
		if err != nil {
			return "", err
		}
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			res += "Virtualhost: " + virtualHost.GetName() + "\n"
			for _, virtualHostRoute := range virtualHost.Routes {
				if virtualHostRoute.Match != nil {
					if virtualHostRoute.Match.GetPath() != "" {
						res += "Match path: " + virtualHostRoute.Match.GetPath() + "\n"
					}
					if virtualHostRoute.Match.GetPrefix() != "" {
						res += "Match prefix: " + virtualHostRoute.Match.GetPrefix() + "\n"
					}
					if virtualHostRoute.Match.GetSafeRegex().GetRegex() != "" {
						res += "Match regex: " + virtualHostRoute.Match.GetSafeRegex().GetRegex() + "\n"
					}
				}
				if virtualHostRoute.Action != nil {
					switch reflect.TypeOf(virtualHostRoute.Action).String() {
					case "*routev3.Route_Route":
						res += "Route action (cluster): " + virtualHostRoute.Action.(*route.Route_Route).Route.ClusterSpecifier.(*route.RouteAction_Cluster).Cluster + "\n"
					case "*routev3.Route_DirectResponse":
						res += "Route action (directResponse): "
						res += fmt.Sprint(virtualHostRoute.Action.(*route.Route_DirectResponse).DirectResponse.GetStatus()) + " "
						res += virtualHostRoute.Action.(*route.Route_DirectResponse).DirectResponse.Body.GetInlineString() + "\n"
					default:
						return "", fmt.Errorf("Route action type is unknown: %s", reflect.TypeOf(virtualHostRoute.Action).String())
					}
				} else {
					return "", fmt.Errorf("Validation: no route action found for virtualhost: %+v", virtualHost)
				}
			}
		}
	}
	return res, nil
}

func (l *Listener) HasMTLSDefault(listenerName, attr string) bool {
	if attr == "envoy.filters.http.router" {
		return true // always allow the router filter
	}
	if attr == "envoy.filters.network.rbac" {
		return true // always allow the rbac filter
	}
	if val, ok := l.mTLSListenerDefaultsMapping[listenerName]; ok {
		switch attr {
		case "envoy.filters.http.ratelimit":
			return val.rateLimit
		case "accessLoggerConfig":
			return val.accessLogConfig
		case "tracing":
			return val.tracing
		case "envoy.filters.http.compressor":
			return val.compression
		case "envoy.ext_authz":
			return val.authz
		case "envoy.filters.http.jwt_authn":
			return false // we don't setup jwt authn on new listeners
		case "envoy.filters.http.lua":
			return true
		}
	}
	return false
}

func (l *Listener) setMTLSDefault(mTLSName, attr string) {
	if mTLSName != "" {
		listenerName := "l_mtls_" + mTLSName
		newDefaults := listenerDefaultsMapping{}
		if existingValues, ok := l.mTLSListenerDefaultsMapping[listenerName]; ok {
			newDefaults = existingValues
		}
		switch attr {
		case "envoy.filters.http.ratelimit":
			newDefaults.rateLimit = true
		case "accessLoggerConfig":
			newDefaults.accessLogConfig = true
		case "tracing":
			newDefaults.tracing = true
		case "envoy.filters.http.compressor":
			newDefaults.compression = true
		case "envoy.ext_authz":
			newDefaults.authz = true
		case "envoy.filters.http.lua":
			newDefaults.luaFilter = true
		}

		l.mTLSListenerDefaultsMapping[listenerName] = newDefaults
	}
}
