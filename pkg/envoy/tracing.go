package envoy

import (
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoyType "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

type Tracing struct{}

func newTracing() *Tracing {
	return &Tracing{}
}

func (t *Tracing) updateListenersWithTracing(cache *WorkQueueCache, tracing TracingParams) error {
	// update listener
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if isDefaultListener(ll.GetName()) || "l_mtls_"+tracing.Listener.MTLS == ll.GetName() { // only update listener if it is default listener / mTLS listener is selected
			for filterchainID := range ll.FilterChains {
				for filterID := range ll.FilterChains[filterchainID].Filters {
					// get manager
					manager, err := getManager((ll.FilterChains[filterchainID].Filters[filterID].ConfigType).(*api.Filter_TypedConfig))
					if err != nil {
						return err
					}

					tracingConfig := &tracev3.DatadogConfig{
						CollectorCluster: tracing.CollectorCluster,
						ServiceName:      "envoy",
					}
					tracingConfigEncoded, err := anypb.New(tracingConfig)
					if err != nil {
						return err
					}

					manager.Tracing = &hcm.HttpConnectionManager_Tracing{
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
