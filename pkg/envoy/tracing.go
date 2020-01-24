package envoy

import (
	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	envoyType "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/golang/protobuf/ptypes"
)

type Tracing struct{}

func newTracing() *Tracing {
	return &Tracing{}
}

func (t *Tracing) updateListenersWithTracing(cache *WorkQueueCache, tracing TracingParams) error {
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

				manager.Tracing = &hcm.HttpConnectionManager_Tracing{
					ClientSampling:  &envoyType.Percent{Value: tracing.ClientSampling},
					RandomSampling:  &envoyType.Percent{Value: tracing.RandomSampling},
					OverallSampling: &envoyType.Percent{Value: tracing.OverallSampling},
				}

				// update manager in cache
				pbst, err := ptypes.MarshalAny(&manager)
				if err != nil {
					return err
				}
				ll.FilterChains[filterchainID].Filters[filterID].ConfigType = &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				}

			}

		}

	}

	return nil
}
