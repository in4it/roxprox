package envoy

import (
	"fmt"
	"sort"
	"time"

	corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	route "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	jwtAuth "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/jwt_authn/v2alpha"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher"
	"github.com/golang/protobuf/ptypes"
)

type JwtProvider struct{}

func newJwtProvider() *JwtProvider {
	return &JwtProvider{}
}

func (j *JwtProvider) getJwtRule(conditions Conditions, clusterName string, jwtProvider string, matchType string) []*jwtAuth.RequirementRule {
	var rules []*jwtAuth.RequirementRule
	prefix := "/"

	jwtAuthRequirement := &jwtAuth.JwtRequirement{
		RequiresType: &jwtAuth.JwtRequirement_ProviderName{
			ProviderName: jwtProvider,
		},
	}

	if conditions.Prefix != "" {
		prefix = conditions.Prefix
	}
	var hostnameHeaders []*route.HeaderMatcher
	var methodHeaders []*route.HeaderMatcher
	if conditions.Hostname != "" {
		hostnameHeaders = append(hostnameHeaders, &route.HeaderMatcher{
			Name: ":authority",
			HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
				ExactMatch: conditions.Hostname,
			},
		})
	}
	if len(conditions.Methods) > 0 {
		sort.Strings(conditions.Methods)
		for _, method := range conditions.Methods {
			methodHeaders = append(methodHeaders, &route.HeaderMatcher{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_ExactMatch{
					ExactMatch: method,
				},
			})
		}
	}
	if matchType == "prefix" {
		if len(methodHeaders) == 0 {
			rules = append(rules, &jwtAuth.RequirementRule{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: prefix,
					},
					Headers: hostnameHeaders,
				},
				Requires: jwtAuthRequirement,
			})
		} else {
			for _, methodHeader := range methodHeaders {
				rules = append(rules, &jwtAuth.RequirementRule{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Prefix{
							Prefix: prefix,
						},
						Headers: append(hostnameHeaders, methodHeader),
					},
					Requires: jwtAuthRequirement,
				})
			}
		}
	} else if matchType == "path" {
		if len(methodHeaders) == 0 {
			rules = append(rules, &jwtAuth.RequirementRule{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Path{
						Path: conditions.Path,
					},
					Headers: hostnameHeaders,
				},
				Requires: jwtAuthRequirement,
			})
		} else {
			for _, methodHeader := range methodHeaders {
				rules = append(rules, &jwtAuth.RequirementRule{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Path{
							Path: conditions.Path,
						},
						Headers: append(hostnameHeaders, methodHeader),
					},
					Requires: jwtAuthRequirement,
				})
			}
		}
	} else if matchType == "regex" {
		if len(methodHeaders) == 0 {
			rules = append(rules, &jwtAuth.RequirementRule{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_SafeRegex{
						SafeRegex: &matcher.RegexMatcher{
							Regex:      conditions.Regex,
							EngineType: &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}},
						},
					},
					Headers: hostnameHeaders,
				},
				Requires: jwtAuthRequirement,
			})
		} else {
			for _, methodHeader := range methodHeaders {
				rules = append(rules, &jwtAuth.RequirementRule{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_SafeRegex{
							SafeRegex: &matcher.RegexMatcher{
								Regex:      conditions.Regex,
								EngineType: &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}},
							},
						},
						Headers: append(hostnameHeaders, methodHeader),
					},
					Requires: jwtAuthRequirement,
				})
			}
		}
	}

	return rules
}

func (j *JwtProvider) jwtRuleExist(rules []*jwtAuth.RequirementRule, rule *jwtAuth.RequirementRule) bool {
	ruleFound := false
	for _, v := range rules {
		if routeMatchEqual(v.Match, rule.Match) && v.Requires.RequiresType.(*jwtAuth.JwtRequirement_ProviderName).ProviderName == rule.Requires.RequiresType.(*jwtAuth.JwtRequirement_ProviderName).ProviderName {
			ruleFound = true
		}
	}
	return ruleFound
}
func (j *JwtProvider) getJwtConfig(auth Auth) *jwtAuth.JwtAuthentication {
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
						HttpUri: &corev2.HttpUri{
							Uri:     auth.RemoteJwks,
							Timeout: ptypes.DurationProto(30 * time.Second),
							HttpUpstreamType: &corev2.HttpUri_Cluster{
								Cluster: "jwtProvider_" + auth.JwtProvider,
							},
						},
					},
				},
			},
		},
	}
}
func (j *JwtProvider) updateListenerWithJwtProvider(cache *WorkQueueCache, params ListenerParams) error {
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
		// add routes to jwtProvider
		var jwtConfig jwtAuth.JwtAuthentication
		if getListenerHTTPFilterIndex("envoy.filters.http.jwt_authn", manager.HttpFilters) != -1 {
			jwtConfig, err = getListenerHTTPFilterJwtAuth(manager.HttpFilters)
			if err != nil {
				return err
			}
		}
		if jwtConfig.Providers == nil {
			jwtConfig.Providers = make(map[string]*jwtAuth.JwtProvider)
		}
		jwtNewConfig := j.getJwtConfig(params.Auth)
		jwtConfig.Providers[params.Auth.JwtProvider] = jwtNewConfig.Providers[params.Auth.JwtProvider]
		logger.Debugf("Adding/updating %s to jwt config", params.Auth.JwtProvider)

		jwtConfigEncoded, err := ptypes.MarshalAny(&jwtConfig)
		if err != nil {
			panic(err)
		}

		updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.filters.http.jwt_authn", jwtConfigEncoded)

		pbst, err := ptypes.MarshalAny(&manager)
		if err != nil {
			panic(err)
		}
		ll.FilterChains[0].Filters[0].ConfigType = &listener.Filter_TypedConfig{
			TypedConfig: pbst,
		}
	}
	return nil
}

func (j *JwtProvider) UpdateJwtRule(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {
	if params.Auth.JwtProvider == "" {
		return fmt.Errorf("UpdateJwtRule without JwtProvider specified")
	}

	var listenerKey = -1

	tls, _, _, listenerName, _, matchType := getListenerAttributes(params, paramsTLS)

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
	} else {
		manager, err = getListenerHTTPConnectionManager(ll)
		if err != nil {
			return err
		}
	}

	// add routes to jwtProvider
	var jwtConfig jwtAuth.JwtAuthentication
	if getListenerHTTPFilterIndex("envoy.filters.http.jwt_authn", manager.HttpFilters) != -1 {
		jwtConfig, err = getListenerHTTPFilterJwtAuth(manager.HttpFilters)
		if err != nil {
			return err
		}
	}

	// find provider
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
		jwtNewConfig := j.getJwtConfig(params.Auth)
		jwtConfig.Providers[params.Auth.JwtProvider] = jwtNewConfig.Providers[params.Auth.JwtProvider]
		logger.Debugf("adding provider %s to jwt config", params.Auth.JwtProvider)
	}

	// update routes
	newJwtRules := j.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider, matchType)
	for _, newJwtRule := range newJwtRules {
		if j.jwtRuleExist(jwtConfig.Rules, newJwtRule) {
			logger.Debugf("JWT Rule already exists, not adding route for %s", params.Name)
		} else {
			jwtConfig.Rules = append(jwtConfig.Rules, newJwtRule)
		}
	}
	jwtConfigEncoded, err := ptypes.MarshalAny(&jwtConfig)
	if err != nil {
		panic(err)
	}

	updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.filters.http.jwt_authn", jwtConfigEncoded)

	pbst, err := ptypes.MarshalAny(&manager)
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

	return nil

}
func (j *JwtProvider) DeleteJwtRule(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams) error {

	// TODO: only delete jwt rule

	if params.Auth.JwtProvider == "" {
		return fmt.Errorf("DeleteJwtRule: no JwtProvider found")
	}

	tls, _, _, _, _, matchType := getListenerAttributes(params, paramsTLS)

	listenerKeyHTTP := -1
	listenerKeyTLS := -1
	for k, listener := range cache.listeners {
		if (listener.(*api.Listener)).Name == "l_http" {
			listenerKeyHTTP = k
		} else if (listener.(*api.Listener)).Name == "l_tls" {
			listenerKeyTLS = k
		}
	}

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

	// delete jwt rule if necessary
	jwtConfig, err := getListenerHTTPFilterJwtAuth(manager.HttpFilters)
	if err != nil {
		return err
	}
	if _, ok := jwtConfig.Providers[params.Auth.JwtProvider]; ok {
		// update rules
		rules := j.getJwtRule(params.Conditions, params.Name, params.Auth.JwtProvider, matchType)
		for _, rule := range rules {
			index := j.requirementRuleIndex(jwtConfig.Rules, rule)
			jwtConfig.Rules = append(jwtConfig.Rules[:index], jwtConfig.Rules[index+1:]...)
		}
		jwtConfigEncoded, err := ptypes.MarshalAny(&jwtConfig)
		if err != nil {
			panic(err)
		}

		updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.filters.http.jwt_authn", jwtConfigEncoded)
	} else {
		logger.Debugf("Couldn't find jwt provider %s during deleteRoute", params.Auth.JwtProvider)
	}

	pbst, err := ptypes.MarshalAny(&manager)
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

func (j *JwtProvider) requirementRuleIndex(rules []*jwtAuth.RequirementRule, rule *jwtAuth.RequirementRule) int {
	for index, v := range rules {
		if cmpMatch(v.Match, rule.Match) && v.Requires.RequiresType.(*jwtAuth.JwtRequirement_ProviderName).ProviderName == rule.Requires.RequiresType.(*jwtAuth.JwtRequirement_ProviderName).ProviderName {
			return index
		}
	}
	return -1
}
