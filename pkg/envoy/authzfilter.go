package envoy

import (
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/ext_authz/v2"
	"github.com/gogo/protobuf/types"
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
				manager, err := getManager((ll.FilterChains[filterchainID].Filters[filterID].ConfigType).(*listener.Filter_TypedConfig))
				if err != nil {
					return err
				}

				// config
				authzConfig, err := a.getAuthzFilter(params)
				if err != nil {
					return err
				}

				// encode config
				authzConfigEncoded, err := types.MarshalAny(authzConfig)
				if err != nil {
					panic(err)
				}

				// update http filter
				updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.ext_authz", authzConfigEncoded)

			}

		}

	}

	return nil
}

func (a *AuthzFilter) getAuthzFilter(params ListenerParams) (*extAuthz.ExtAuthz, error) {
	timeout, err := time.ParseDuration(params.Authz.Timeout)
	if err != nil {
		return nil, err
	}
	return &extAuthz.ExtAuthz{
		FailureModeAllow: params.Authz.FailureModeAllow,
		Services: &extAuthz.ExtAuthz_GrpcService{
			GrpcService: &core.GrpcService{
				Timeout: types.DurationProto(timeout),
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: "authz_" + params.Name,
					},
				},
			},
		},
	}, nil
}
