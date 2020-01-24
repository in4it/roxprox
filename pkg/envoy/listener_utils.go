package envoy

import (
	"fmt"
	"reflect"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	route "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/ext_authz/v2"
	jwtAuth "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/jwt_authn/v2alpha"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
)

// static listener functions
func getListenerHTTPConnectionManager(ll *api.Listener) (hcm.HttpConnectionManager, error) {
	var manager hcm.HttpConnectionManager
	var err error
	if len(ll.FilterChains) == 0 {
		return manager, fmt.Errorf("No filterchains found in listener %s", ll.Name)
	}
	if len(ll.FilterChains[0].Filters) == 0 {
		return manager, fmt.Errorf("No filters found in listener %s", ll.Name)
	}
	manager, err = getManager((ll.FilterChains[0].Filters[0].ConfigType).(*listener.Filter_TypedConfig))
	if err != nil {
		return manager, err
	}
	return manager, nil
}
func getManager(typedConfig *listener.Filter_TypedConfig) (hcm.HttpConnectionManager, error) {
	var manager hcm.HttpConnectionManager

	err := ptypes.UnmarshalAny(typedConfig.TypedConfig, &manager)
	if err != nil {
		return manager, err
	}

	return manager, nil
}
func getListenerHTTPConnectionManagerTLS(ll *api.Listener, hostname string) (hcm.HttpConnectionManager, error) {
	var err error
	var manager hcm.HttpConnectionManager

	filterId := getFilterChainId(ll.FilterChains, hostname)

	if filterId == -1 {
		return manager, fmt.Errorf(Error_NoFilterChainFound)
	} else {
		if len(ll.FilterChains[filterId].Filters) == 0 {
			return manager, fmt.Errorf(Error_NoFilterFound)
		}
		manager, err = getManager(ll.FilterChains[filterId].Filters[0].ConfigType.(*listener.Filter_TypedConfig))
		if err != nil {
			return manager, err
		}
	}

	return manager, nil
}
func getFilterChainId(filterChains []*listener.FilterChain, hostname string) int {
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

func getListenerHTTPFilterJwtAuth(httpFilter []*hcm.HttpFilter) (jwtAuth.JwtAuthentication, error) {
	var jwtConfig jwtAuth.JwtAuthentication
	httpFilterPos := getListenerHTTPFilterIndex("envoy.filters.http.jwt_authn", httpFilter)
	if httpFilterPos == -1 {
		return jwtConfig, fmt.Errorf("HttpFilter for jwt missing")
	}
	err := ptypes.UnmarshalAny(httpFilter[httpFilterPos].GetTypedConfig(), &jwtConfig)
	if err != nil {
		return jwtConfig, err
	}
	return jwtConfig, nil
}
func getListenerHTTPFilterAuthz(httpFilter []*hcm.HttpFilter) (extAuthz.ExtAuthz, error) {
	var authzConfig extAuthz.ExtAuthz
	httpFilterPos := getListenerHTTPFilterIndex("envoy.ext_authz", httpFilter)
	if httpFilterPos == -1 {
		return authzConfig, fmt.Errorf("HttpFilter for authz missing")
	}
	err := ptypes.UnmarshalAny(httpFilter[httpFilterPos].GetTypedConfig(), &authzConfig)
	if err != nil {
		return authzConfig, err
	}
	return authzConfig, nil
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
		listenerPort = 10000
		listenerName = "l_http"
	}
	return tls, targetPrefix, virtualHostName, listenerName, listenerPort, matchType
}
func updateHTTPFilterWithConfig(httpFilter *[]*hcm.HttpFilter, filterName string, filterConfig *any.Any) {
	// check whether filter exists
	httpFilterPos := getListenerHTTPFilterIndex(filterName, *httpFilter)

	if httpFilterPos == -1 {
		// prepend new httpFilter if the filter is not added yet
		*httpFilter = append(
			[]*hcm.HttpFilter{{
				Name: filterName,
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: filterConfig,
				}},
			}, *httpFilter...)
	} else {
		// filter exists: copy filter and update config of the filter
		(*httpFilter)[httpFilterPos].ConfigType = &hcm.HttpFilter_TypedConfig{TypedConfig: filterConfig}
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

		if aa.HeaderMatchSpecifier.(*route.HeaderMatcher_ExactMatch).ExactMatch != bb.HeaderMatchSpecifier.(*route.HeaderMatcher_ExactMatch).ExactMatch {
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
	if a.GetExactMatch() != b.GetExactMatch() {
		return false
	}
	if a.GetInvertMatch() != b.GetInvertMatch() {
		return false
	}
	if a.GetPrefixMatch() != b.GetPrefixMatch() {
		return false
	}
	if a.GetRangeMatch() != b.GetRangeMatch() {
		return false
	}
	if a.GetRegexMatch() != b.GetRegexMatch() {
		return false
	}
	if a.GetPresentMatch() != b.GetPresentMatch() {
		return false
	}
	if a.GetSafeRegexMatch() != b.GetSafeRegexMatch() {
		return false
	}
	if a.GetSuffixMatch() != b.GetSuffixMatch() {
		return false
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
	if a.GetRegex() != b.GetRegex() {
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
func routeActionEqual(a, b *route.Route) bool {
	if reflect.TypeOf(a.Action).String() != reflect.TypeOf(b.Action).String() {
		return false
	}
	switch reflect.TypeOf(a.Action).String() {
	case "*envoy_api_v2_route.Route_Route":
		cluster1 := a.Action.(*route.Route_Route).Route.ClusterSpecifier.(*route.RouteAction_Cluster).Cluster
		cluster2 := b.Action.(*route.Route_Route).Route.ClusterSpecifier.(*route.RouteAction_Cluster).Cluster
		if cluster1 != cluster2 {
			return false
		}
	case "*envoy_api_v2_route.Route_DirectResponse":
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
