package envoy

import (
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"google.golang.org/protobuf/types/known/anypb"
	any "google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

type AuthzFilter struct{}

func newAuthzFilter() *AuthzFilter {
	return &AuthzFilter{}
}

func (a *AuthzFilter) updateListenersWithAuthzFilter(cache *WorkQueueCache, params ListenerParams) error {
	// update listener
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if isDefaultListener(ll.GetName()) || "l_mtls_"+params.Listener.MTLS == ll.GetName() { // only update listener if it is default listener / mTLS listener is selected
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
func (a *AuthzFilter) getAuthzFilterEncoded(params ListenerParams) (*any.Any, error) {
	authzConfig, err := a.getAuthzFilter(params)
	if err != nil {
		return nil, err
	}
	authzConfigEncoded, err := anypb.New(authzConfig)
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
		TransportApiVersion: core.ApiVersion_V3,
		FailureModeAllow:    params.Authz.FailureModeAllow,
		Services: &extAuthz.ExtAuthz_GrpcService{
			GrpcService: &core.GrpcService{
				Timeout: durationpb.New(timeout),
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
						ClusterName: params.Name,
					},
				},
			},
		},
	}, nil
}
