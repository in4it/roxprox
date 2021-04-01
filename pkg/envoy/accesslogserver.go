package envoy

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	alf "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"
)

type AccessLogServer struct{}

func newAccessLogServer() *AccessLogServer {
	return &AccessLogServer{}
}

func (c *AccessLogServer) updateListenersWithAccessLogServer(cache *WorkQueueCache, params AccessLogServerParams) error {
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
					accessLogConfig, err := c.getAccessLoggerConfig(params)
					if err != nil {
						return err
					}

					manager.AccessLog = accessLogConfig

					// update manager in cache
					pbst, err := ptypes.MarshalAny(manager)
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

func (c *AccessLogServer) getAccessLoggerConfig(params AccessLogServerParams) ([]*alf.AccessLog, error) {
	if params.Name != "" {
		alsConfig := &als.HttpGrpcAccessLogConfig{
			CommonConfig: &als.CommonGrpcAccessLogConfig{
				TransportApiVersion: core.ApiVersion_V3,
				LogName:             params.Name,
				GrpcService: &core.GrpcService{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
							ClusterName: params.Name,
						},
					},
				},
			},
			AdditionalRequestHeadersToLog:  params.AdditionalRequestHeadersToLog,
			AdditionalResponseHeadersToLog: params.AdditionalResponseHeadersToLog,
		}
		alsConfigPbst, err := ptypes.MarshalAny(alsConfig)
		if err != nil {
			return nil, err
		}

		return []*alf.AccessLog{{
			Name: wellknown.HTTPGRPCAccessLog,
			ConfigType: &alf.AccessLog_TypedConfig{
				TypedConfig: alsConfigPbst,
			},
		}}, nil
	}
	return nil, nil
}
