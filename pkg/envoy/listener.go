package envoy

import (
	"fmt"
	"sort"
	"strings"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/gogo/protobuf/types"
)

const Error_NoFilterChainFound = "NoFilterChainFound"
const Error_NoFilterFound = "NoFilterFound"

type Listener struct {
	httpFilter []*hcm.HttpFilter
}

func newListener() *Listener {
	listener := &Listener{}
	listener.httpFilter = []*hcm.HttpFilter{
		{
			Name: util.Router,
		},
	}
	return listener
}

func (l *Listener) newTLSFilterChain(params TLSParams) *listener.FilterChain {
	return &listener.FilterChain{
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
			filterId := getFilterChainId(ll.FilterChains, params.Domain)
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
			routeSpecifier, err := l.getListenerRouteSpecifier(manager)
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
	return routeSpecifier, nil
}

func (l *Listener) getVirtualHost(hostname, targetHostname, targetPrefix, clusterName, virtualHostName string, methods []string, matchType string) *route.VirtualHost {
	var hostRewriteSpecifier *route.RouteAction_HostRewrite
	var routes []*route.Route

	if hostname == "" {
		hostname = "*"
	}

	if targetHostname != "" {
		hostRewriteSpecifier = &route.RouteAction_HostRewrite{
			HostRewrite: targetHostname,
		}
	}

	routeAction := &route.Route_Route{
		Route: &route.RouteAction{
			HostRewriteSpecifier: hostRewriteSpecifier,
			ClusterSpecifier: &route.RouteAction_Cluster{
				Cluster: clusterName,
			},
		},
	}

	var headers []*route.HeaderMatcher
	if len(methods) > 0 {
		sort.Strings(methods)
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
	} else if matchType == "path" {
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
	} else if matchType == "regex" {
		if len(headers) == 0 {
			routes = append(routes, &route.Route{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Regex{
						Regex: targetPrefix,
					},
				},
				Action: routeAction,
			})
		} else {
			for _, header := range headers {
				routes = append(routes, &route.Route{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Regex{
							Regex: targetPrefix,
						},
						Headers: []*route.HeaderMatcher{header},
					},
					Action: routeAction,
				})
			}
		}
	}

	return &route.VirtualHost{
		Name:    virtualHostName,
		Domains: []string{hostname},

		Routes: routes,
	}
}

func (l *Listener) newTLSFilter(params ListenerParams, paramsTLS TLSParams, listenerName string) []*listener.Filter {
	httpFilters := l.newHTTPRouterFilter()
	newEmptyVirtualHost := &route.VirtualHost{
		Name:    "v_" + params.Conditions.Hostname,
		Domains: []string{params.Conditions.Hostname},
		Routes:  []*route.Route{},
	}
	manager := l.newManager(strings.Replace(listenerName, "l_", "r_", 1), []*route.VirtualHost{newEmptyVirtualHost}, httpFilters)
	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}
	return []*listener.Filter{{
		Name: util.HTTPConnectionManager,
		ConfigType: &listener.Filter_TypedConfig{
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
	var manager hcm.HttpConnectionManager
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
		}
	}

	if virtualHostKey >= 0 {
		for _, newRoute := range v.Routes {
			if l.routeExist(routeSpecifier.RouteConfig.VirtualHosts[virtualHostKey].Routes, newRoute) {
				logger.Debugf("Route already exists, not adding route for %s", v.Name)
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
	pbst, err := types.MarshalAny(&manager)
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
	ll.FilterChains[filterId].Filters[0].ConfigType = &listener.Filter_TypedConfig{
		TypedConfig: pbst,
	}

	logger.Debugf("Updated listener with new Virtualhost")

	return nil
}

func (l *Listener) routeExist(routes []*route.Route, route *route.Route) bool {
	routeFound := false
	for _, v := range routes {
		if cmpMatch(v.Match, route.Match) && v.Action.Equal(route.Action) {
			routeFound = true
		}
	}
	return routeFound
}
func (l *Listener) routeIndex(routes []*route.Route, route *route.Route) int {
	for index, v := range routes {
		if cmpMatch(v.Match, route.Match) && v.Action.Equal(route.Action) {
			return index
		}
	}
	return -1
}

func (l *Listener) newManager(routeName string, virtualHosts []*route.VirtualHost, httpFilters []*hcm.HttpFilter) *hcm.HttpConnectionManager {
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

	tls, _, _, listenerName, listenerPort, _ := getListenerAttributes(params, paramsTLS)

	logger.Infof("Creating listener " + listenerName)

	httpFilters := l.newHTTPRouterFilter()
	manager := l.newManager(strings.Replace(listenerName, "l_", "r_", 1), []*route.VirtualHost{}, httpFilters)

	pbst, err := types.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	newListener := &api.Listener{
		Name: listenerName,
		Address: &core.Address{
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
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
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
		newListener.ListenerFilters = []*listener.ListenerFilter{
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

	tls, targetPrefix, virtualHostname, _, _, matchType := getListenerAttributes(params, paramsTLS)

	// http listener
	var manager hcm.HttpConnectionManager
	var err error

	var ll *api.Listener
	if tls {
		ll = cache.listeners[listenerKeyTLS].(*api.Listener)
		manager, err = getListenerHTTPConnectionManagerTLS(ll, params.Conditions.Hostname)
	} else {
		ll = cache.listeners[listenerKeyHTTP].(*api.Listener)
		manager, err = getListenerHTTPConnectionManager(ll)
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
	pbst, err := types.MarshalAny(&manager)
	if err != nil {
		panic(err)
	}

	filterId := -1
	if tls {
		filterId = getFilterChainId(ll.FilterChains, params.Conditions.Hostname)
	} else {
		filterId = 0
	}

	ll.FilterChains[filterId].Filters[0].ConfigType = &listener.Filter_TypedConfig{
		TypedConfig: pbst,
	}

	return nil
}

func (l *Listener) validateListeners(listeners []cache.Resource, clusterNames []string) (bool, error) {
	logger.Debugf("Validating config...")
	for listenerKey := range listeners {
		ll := listeners[listenerKey].(*api.Listener)

		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			return false, err
		}
		routeSpecifier, err := l.getListenerRouteSpecifier(manager)
		if err != nil {
			return false, err
		}
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, virtualHostRoute := range virtualHost.Routes {
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

			}
		}
	}
	return true, nil
}

func (l *Listener) updateDefaultHTTPRouterFilter(filterName string, filterConfig *types.Any) {
	updateHTTPFilterWithConfig(&l.httpFilter, filterName, filterConfig)
}

func (l *Listener) newHTTPRouterFilter() []*hcm.HttpFilter {
	return l.httpFilter
}
