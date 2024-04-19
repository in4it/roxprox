package envoy

import (
	"fmt"
	"reflect"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	jwtAuth "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	any "google.golang.org/protobuf/types/known/anypb"
)

// static listener functions
func getListenerHTTPConnectionManager(ll *api.Listener) (*hcm.HttpConnectionManager, error) {
	var manager *hcm.HttpConnectionManager
	var err error
	if len(ll.FilterChains) == 0 {
		return manager, fmt.Errorf("No filterchains found in listener %s", ll.Name)
	}
	if len(ll.FilterChains[0].Filters) == 0 {
		return manager, fmt.Errorf("No filters found in listener %s", ll.Name)
	}
	manager, err = getManager((ll.FilterChains[0].Filters[getFilterIndexByName(ll.FilterChains[0].Filters, Envoy_HTTP_Filter)].ConfigType).(*api.Filter_TypedConfig))
	if err != nil {
		return manager, err
	}
	return manager, nil
}
func getManager(typedConfig *api.Filter_TypedConfig) (*hcm.HttpConnectionManager, error) {
	var manager hcm.HttpConnectionManager

	err := anypb.UnmarshalTo(typedConfig.TypedConfig, &manager, proto.UnmarshalOptions{})
	if err != nil {
		return &manager, err
	}

	return &manager, nil
}

func getTransportSocketDownStreamTlsSocket(typedConfig *core.TransportSocket_TypedConfig) (*tls.DownstreamTlsContext, error) {
	var tlsContext tls.DownstreamTlsContext

	err := anypb.UnmarshalTo(typedConfig.TypedConfig, &tlsContext, proto.UnmarshalOptions{})
	if err != nil {
		return &tlsContext, err
	}

	return &tlsContext, nil
}

func getListenerRouteSpecifier(manager *hcm.HttpConnectionManager) (*hcm.HttpConnectionManager_RouteConfig, error) {
	var routeSpecifier *hcm.HttpConnectionManager_RouteConfig
	routeSpecifier = manager.RouteSpecifier.(*hcm.HttpConnectionManager_RouteConfig)
	return routeSpecifier, nil
}

func getListenerHTTPConnectionManagerTLS(ll *api.Listener, hostname string) (*hcm.HttpConnectionManager, error) {
	var err error
	var manager *hcm.HttpConnectionManager

	filterId := getFilterChainId(ll.FilterChains, hostname)

	if filterId == -1 {
		return manager, fmt.Errorf(Error_NoFilterChainFound)
	} else {
		if len(ll.FilterChains[filterId].Filters) == 0 {
			return manager, fmt.Errorf(Error_NoFilterFound)
		}
		manager, err = getManager(ll.FilterChains[filterId].Filters[0].ConfigType.(*api.Filter_TypedConfig))
		if err != nil {
			return manager, err
		}
	}

	return manager, nil
}
func getFilterChainId(filterChains []*api.FilterChain, hostname string) int {
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

func getListenerHTTPFilterIndex(filterName string, httpFilter []*hcm.HttpFilter) int {
	for k, v := range httpFilter {
		if v.Name == filterName {
			return k
		}
	}
	return -1
}

func getListenerHTTPFilterJwtAuth(httpFilter []*hcm.HttpFilter) (*jwtAuth.JwtAuthentication, error) {
	var jwtConfig jwtAuth.JwtAuthentication
	httpFilterPos := getListenerHTTPFilterIndex("envoy.filters.http.jwt_authn", httpFilter)
	if httpFilterPos == -1 {
		return &jwtConfig, fmt.Errorf("HttpFilter for jwt missing")
	}
	err := anypb.UnmarshalTo(httpFilter[httpFilterPos].GetTypedConfig(), &jwtConfig, proto.UnmarshalOptions{})
	if err != nil {
		return &jwtConfig, err
	}
	return &jwtConfig, nil
}
func getListenerHTTPFilterAuthz(httpFilter []*hcm.HttpFilter) (*extAuthz.ExtAuthz, error) {
	var authzConfig extAuthz.ExtAuthz
	httpFilterPos := getListenerHTTPFilterIndex("envoy.ext_authz", httpFilter)
	if httpFilterPos == -1 {
		return &authzConfig, fmt.Errorf("HttpFilter for authz missing")
	}
	err := anypb.UnmarshalTo(httpFilter[httpFilterPos].GetTypedConfig(), &authzConfig, proto.UnmarshalOptions{})
	if err != nil {
		return &authzConfig, err
	}
	return &authzConfig, nil
}

func getListenerAttributes(params ListenerParams, paramsTLS TLSParams) (bool, string, string, string, uint32, string) {
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
	if params.Conditions.Regex != "" {
		matchType = "regex"
		targetPrefix = params.Conditions.Regex
	}

	// default to prefix if path/prefix/regex is not defined
	if params.Conditions.Prefix == "" && params.Conditions.Path == "" && params.Conditions.Regex == "" {
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
		if params.Listener.MTLS != "" {
			listenerPort = uint32(params.Listener.Port)
			listenerName = "l_mtls_" + params.Listener.MTLS
		} else {
			listenerPort = 10000
			listenerName = "l_http"
		}
	}
	return tls, targetPrefix, virtualHostName, listenerName, listenerPort, matchType
}
func updateHTTPFilterWithConfig(httpFilter *[]*hcm.HttpFilter, filterName string, filterConfig *anypb.Any) {
	// check whether filter exists
	httpFilterPos := getListenerHTTPFilterIndex(filterName, *httpFilter)

	if httpFilterPos == -1 {
		prependHTTPFilterWithConfig(httpFilter, filterName, filterConfig)
	} else {
		// filter exists: copy filter and update config of the filter
		(*httpFilter)[httpFilterPos].ConfigType = &hcm.HttpFilter_TypedConfig{TypedConfig: filterConfig}
	}
}

func prependHTTPFilterWithConfig(httpFilter *[]*hcm.HttpFilter, filterName string, filterConfig *any.Any) {
	// prepend new httpFilter if the filter is not added yet
	corsIndex := getListenerHTTPFilterIndex("envoy.filters.http.cors", *httpFilter)
	if corsIndex >= 0 {
		*httpFilter = append((*httpFilter)[:corsIndex+1], (*httpFilter)[corsIndex:]...)
		(*httpFilter)[corsIndex] = &hcm.HttpFilter{
			Name: filterName,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: filterConfig,
			},
		}
	} else {
		*httpFilter = append(
			[]*hcm.HttpFilter{{
				Name: filterName,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: filterConfig,
				}},
			}, *httpFilter...)
	}
}

func cmpMatch(a *route.RouteMatch, b *route.RouteMatch) bool {
	if a.GetPath() != b.GetPath() {
		return false
	}
	if a.GetPrefix() != b.GetPrefix() {
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
			logger.Tracef("cmpMatch: mismatch in header name ")
			return false
		}

		if aa.HeaderMatchSpecifier.(*route.HeaderMatcher_StringMatch).StringMatch.GetExact() != bb.HeaderMatchSpecifier.(*route.HeaderMatcher_StringMatch).StringMatch.GetExact() {
			logger.Tracef("cmpMatch: mismatch in header value ")
			return false
		}
	}

	if !routeMatchEqual(a, b) {
		return false
	}

	return true
}

func headerMatchEqual(a, b *route.HeaderMatcher) bool {
	if a.GetName() != b.GetName() {
		return false
	}
	aStringMatch := a.GetStringMatch()
	bStringMatch := b.GetStringMatch()
	if aStringMatch.GetExact() != bStringMatch.GetExact() {
		return false
	}
	if aStringMatch.IgnoreCase != bStringMatch.IgnoreCase {
		return false
	}
	if aStringMatch.GetPrefix() != bStringMatch.GetPrefix() {
		return false
	}
	if aStringMatch.GetSuffix() != bStringMatch.GetSuffix() {
		return false
	}
	if aStringMatch.GetContains() != bStringMatch.GetContains() {
		return false
	}
	if aStringMatch.GetSafeRegex().GetRegex() != bStringMatch.GetSafeRegex().GetRegex() {
		return false
	}
	return true
}

func regexMatchEqual(a, b *matcher.RegexMatcher) bool {
	if a != nil {
		if b == nil {
			return false
		}
		if a.Regex != b.Regex {
			return false
		}
	}
	if b != nil {
		if a == nil {
			return false
		}
		if a.Regex != b.Regex {
			return false
		}
	}
	return true
}

func routeMatchEqual(a, b *route.RouteMatch) bool {
	if a.GetPrefix() != b.GetPrefix() {
		return false
	}
	if a.GetPath() != b.GetPath() {
		return false
	}
	if !regexMatchEqual(a.GetSafeRegex(), b.GetSafeRegex()) {
		return false
	}

	for _, v1 := range a.GetHeaders() {
		isMatch := false
		for _, v2 := range b.GetHeaders() {
			if headerMatchEqual(v1, v2) {
				isMatch = true
			}
		}
		if !isMatch {
			return false
		}
	}
	return true
}

func cmpRoutePrefix(a, b *route.Route) bool {
	if reflect.TypeOf(a.Action).String() != reflect.TypeOf(b.Action).String() {
		return false
	}
	switch reflect.TypeOf(a.Action).String() {
	case "*routev3.Route_Route":
		route1 := a.Action.(*route.Route_Route).Route
		route2 := b.Action.(*route.Route_Route).Route

		if route1.PrefixRewrite != route2.PrefixRewrite {
			return false
		}
		if route1.RegexRewrite != nil && route2.RegexRewrite == nil {
			return false
		}
		if route2.RegexRewrite != nil && route1.RegexRewrite == nil {
			return false
		}
		if route1.RegexRewrite != nil && route2.RegexRewrite != nil {
			if route1.RegexRewrite.Substitution != route2.RegexRewrite.Substitution {
				return false
			}
			if route1.RegexRewrite.Pattern != nil && route2.RegexRewrite.Pattern == nil {
				return false
			}
			if route1.RegexRewrite.Pattern != nil && route2.RegexRewrite.Pattern != nil {
				if route1.RegexRewrite.Pattern.EngineType != route2.RegexRewrite.Pattern.EngineType {
					return false
				}
				if route1.RegexRewrite.Pattern.Regex != route2.RegexRewrite.Pattern.Regex {
					return false
				}
			}
		}
	default:
		return false
	}

	return true

}
func routeActionEqual(a, b *route.Route) bool {
	if reflect.TypeOf(a.Action).String() != reflect.TypeOf(b.Action).String() {
		return false
	}
	switch reflect.TypeOf(a.Action).String() {
	case "*routev3.Route_Route":
		route1 := a.Action.(*route.Route_Route).Route
		route2 := b.Action.(*route.Route_Route).Route
		cluster1 := route1.ClusterSpecifier.(*route.RouteAction_Cluster).Cluster
		cluster2 := route2.ClusterSpecifier.(*route.RouteAction_Cluster).Cluster
		if cluster1 != cluster2 {
			return false
		}
	case "*routev3.Route_DirectResponse":
		status1 := a.Action.(*route.Route_DirectResponse).DirectResponse.GetStatus()
		status2 := b.Action.(*route.Route_DirectResponse).DirectResponse.GetStatus()
		if status1 != status2 {
			return false
		}
	default:
		return false
	}

	return true
}

func listenerExists(listeners []cacheTypes.Resource, params ListenerParams, paramsTLS TLSParams) bool {
	_, _, _, listenerName, _, _ := getListenerAttributes(params, paramsTLS)
	for listenerKey := range listeners {
		ll := listeners[listenerKey].(*api.Listener)
		if ll.Name == listenerName {
			return true
		}
	}
	return false
}

func getListenerIndex(listeners []cacheTypes.Resource, listenerName string) int {
	for listenerKey := range listeners {
		ll := listeners[listenerKey].(*api.Listener)
		if ll.Name == listenerName {
			return listenerKey
		}
	}
	return -1
}

func isDefaultListener(listenerName string) bool {
	if listenerName == "l_tls" || listenerName == "l_http" {
		return true
	}
	return false
}

func getFilterIndexByName(filters []*api.Filter, name string) int {
	for k, filter := range filters {
		if filter.Name == name {
			return k
		}
	}
	return -1
}
