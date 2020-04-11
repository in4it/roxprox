package envoy

import (
	"time"

	corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/ext_authz/v2"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/golang/protobuf/ptypes"
	any "github.com/golang/protobuf/ptypes/any"
)

type AuthzFilter struct{}

func newAuthzFilter() *AuthzFilter {
	return &AuthzFilter{}
}

func (a *AuthzFilter) updateListenersWithAuthzFilter(cache *WorkQueueCache, params ListenerParams) error {
	// update listener
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		for filterchainID := range ll.FilterChains {
			for filterID := range ll.FilterChains[filterchainID].Filters {
				// get manager
				manager, err := getManager((ll.FilterChains[filterchainID].Filters[filterID].ConfigType).(*api.Filter_TypedConfig))
				if err != nil {
					return err
				}

				// get authz config config
				authzConfigEncoded, err := a.getAuthzFilterEncoded(params)
				if err != nil {
					return err
				}

				// update http filter
				updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.ext_authz", authzConfigEncoded)

				// update manager in cache
				pbst, err := ptypes.MarshalAny(&manager)
				if err != nil {
					return err
				}
				ll.FilterChains[filterchainID].Filters[filterID].ConfigType = &api.Filter_TypedConfig{
					TypedConfig: pbst,
				}

			}

		}

	}

	return nil
}
func (a *AuthzFilter) getAuthzFilterEncoded(params ListenerParams) (*any.Any, error) {
	authzConfig, err := a.getAuthzFilter(params)
	if err != nil {
		return nil, err
	}
	authzConfigEncoded, err := ptypes.MarshalAny(authzConfig)
	if err != nil {
		return nil, err
	}
	return authzConfigEncoded, err
}

func (a *AuthzFilter) getAuthzFilter(params ListenerParams) (*extAuthz.ExtAuthz, error) {
	timeout, err := time.ParseDuration(params.Authz.Timeout)
	if err != nil {
		return nil, err
	}
	return &extAuthz.ExtAuthz{
		FailureModeAllow: params.Authz.FailureModeAllow,
		Services: &extAuthz.ExtAuthz_GrpcService{
			GrpcService: &corev2.GrpcService{
				Timeout: ptypes.DurationProto(timeout),
				TargetSpecifier: &corev2.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev2.GrpcService_EnvoyGrpc{
						ClusterName: params.Name,
					},
				},
			},
		},
	}, nil
}
