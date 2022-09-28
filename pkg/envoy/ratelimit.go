package envoy

import (
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rlc "github.com/envoyproxy/go-control-plane/envoy/config/ratelimit/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rl "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	ssl "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/ssl/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

type RateLimit struct {
	enabled map[string]bool
}

func newRateLimit() *RateLimit {
	return &RateLimit{
		enabled: make(map[string]bool),
	}
}

func (r *RateLimit) updateListenersWithRateLimit(cache *WorkQueueCache, params RateLimitParams, rateLimits map[string][]*route.RateLimit) error {
	// update listener
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if (isDefaultListener(ll.GetName()) && !params.Listener.DisableOnDefault) || "l_mtls_"+params.Listener.MTLS == ll.GetName() { // only update listener if it is default listener (and disableOnDefault is not true) / mTLS listener is selected
			for filterchainID := range ll.FilterChains {
				for filterID := range ll.FilterChains[filterchainID].Filters {
					// get manager
					manager, err := getManager((ll.FilterChains[filterchainID].Filters[filterID].ConfigType).(*api.Filter_TypedConfig))
					if err != nil {
						return err
					}

					// get authz config config
					rateLimitConfigEncoded, err := r.getRateLimitConfigEncoded(params)
					if err != nil {
						return err
					}

					if _, enabled := r.enabled[ll.GetName()]; !enabled {
						// update http filter
						updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.filters.http.ratelimit", rateLimitConfigEncoded)
						r.enabled[ll.GetName()] = true
					}

					// update virtualhosts
					routeSpecifier, err := getListenerRouteSpecifier(manager)
					if err != nil {
						return err
					}

					for k := range routeSpecifier.RouteConfig.VirtualHosts {
						if _, ok := rateLimits[ll.GetName()]; ok {
							routeSpecifier.RouteConfig.VirtualHosts[k].RateLimits = rateLimits[ll.GetName()]
						}
					}

					manager.RouteSpecifier = routeSpecifier

					// update manager in cache
					pbst, err := anypb.New(manager)
					if err != nil {
						return err
					}
					ll.FilterChains[filterchainID].Filters[filterID].ConfigType = &api.Filter_TypedConfig{
						TypedConfig: pbst,
					}
				}
			}
		}
	}

	return nil
}

func (r *RateLimit) getRateLimitConfigEncoded(params RateLimitParams) (*anypb.Any, error) {
	rateLimitFilter, err := r.getRateLimitConfig(params)
	if err != nil {
		return nil, err
	}
	if rateLimitFilter == nil {
		return nil, nil
	}
	rateLimitFilterEncoded, err := anypb.New(rateLimitFilter)
	if err != nil {
		return nil, err
	}
	return rateLimitFilterEncoded, nil
}

func (r *RateLimit) getRateLimitConfig(params RateLimitParams) (*rl.RateLimit, error) {
	return &rl.RateLimit{
		Domain: "ingress",
		RateLimitService: &rlc.RateLimitServiceConfig{
			TransportApiVersion: core.ApiVersion_V3,
			GrpcService: &core.GrpcService{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: "ratelimit",
					},
				},
			},
		},
	}, nil

}

func (r *RateLimit) getRateLimitVirtualHostConfig(params RateLimitParams) (*route.RateLimit, error) {
	var actions []*route.RateLimit_Action
	for _, descriptor := range params.Descriptors {
		if descriptor.SourceCluster {
			actions = append(actions, &route.RateLimit_Action{
				ActionSpecifier: &route.RateLimit_Action_SourceCluster_{
					SourceCluster: &route.RateLimit_Action_SourceCluster{},
				},
			})
		}
		if descriptor.DestinationCluster {
			actions = append(actions, &route.RateLimit_Action{
				ActionSpecifier: &route.RateLimit_Action_DestinationCluster_{
					DestinationCluster: &route.RateLimit_Action_DestinationCluster{},
				},
			})
		}
		if descriptor.RemoteAddress {
			actions = append(actions, &route.RateLimit_Action{
				ActionSpecifier: &route.RateLimit_Action_RemoteAddress_{
					RemoteAddress: &route.RateLimit_Action_RemoteAddress{},
				},
			})
		}
		if descriptor.RequestHeader != "" {
			actions = append(actions, &route.RateLimit_Action{
				ActionSpecifier: &route.RateLimit_Action_RequestHeaders_{
					RequestHeaders: &route.RateLimit_Action_RequestHeaders{
						HeaderName:    descriptor.RequestHeader,
						DescriptorKey: "header_" + strings.ToLower(descriptor.RequestHeader),
					},
				},
			})
		}
		if params.Listener.MTLS != "" && descriptor.MTLSSubject {
			extensionConfig, err := anypb.New(&ssl.SubjectInput{})
			if err != nil {
				return nil, err
			}
			actions = append(actions, &route.RateLimit_Action{
				ActionSpecifier: &route.RateLimit_Action_Extension{
					Extension: &core.TypedExtensionConfig{
						Name:        "mtls_subject",
						TypedConfig: extensionConfig,
					},
				},
			})
		}
		actions = append(actions, &route.RateLimit_Action{
			ActionSpecifier: &route.RateLimit_Action_GenericKey_{
				GenericKey: &route.RateLimit_Action_GenericKey{
					DescriptorValue: "__identifier:" + params.Name,
				},
			},
		})
	}
	return &route.RateLimit{
		Actions: actions,
	}, nil

}
