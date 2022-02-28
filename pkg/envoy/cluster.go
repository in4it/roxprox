package envoy

import (
	"fmt"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreams "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const PRESET_CONNECT_TIMEOUT_SECONDS = 2

type Cluster struct {
	DefaultsParams DefaultsParams
}

func newCluster() *Cluster {
	return &Cluster{}
}

func (c *Cluster) findCluster(clusters []cacheTypes.Resource, params ClusterParams) (int, error) {
	for k, v := range clusters {
		if v.(*api.Cluster).Name == params.Name {
			return k, nil
		}
	}
	return -1, fmt.Errorf("Cluster not found")
}
func (c *Cluster) findClusterByName(clusters []cacheTypes.Resource, name string) (int, error) {
	for k, v := range clusters {
		if v.(*api.Cluster).Name == name {
			return k, nil
		}
	}
	return -1, fmt.Errorf("Cluster not found")
}
func (c *Cluster) getAllClusterNames(clusters []cacheTypes.Resource) []string {
	var clusterNames []string
	for _, v := range clusters {
		clusterNames = append(clusterNames, v.(*api.Cluster).Name)
	}
	return clusterNames
}

func (c *Cluster) createCluster(params ClusterParams) *api.Cluster {
	var transportSocket *core.TransportSocket
	if params.Port == 443 {
		tlsContext, err := anypb.New(&tls.UpstreamTlsContext{
			Sni: params.TargetHostname,
		})
		if err != nil {
			panic(err)
		}
		transportSocket = &core.TransportSocket{
			Name: "tls",
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: tlsContext,
			},
		}
	}

	logger.Infof("Creating cluster " + params.Name)

	address := &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address:  params.TargetHostname,
			Protocol: core.SocketAddress_TCP,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: uint32(params.Port),
			},
		},
	}}

	connectTimeout := PRESET_CONNECT_TIMEOUT_SECONDS * time.Second

	if params.ConnectTimeout > 0 {
		connectTimeout = time.Duration(params.ConnectTimeout) * time.Second
	} else { // set default if defined
		if c.DefaultsParams.ConnectTimeout > 0 {
			connectTimeout = time.Duration(c.DefaultsParams.ConnectTimeout) * time.Second
		}
	}

	// add healthchecks
	healthChecks := []*core.HealthCheck{}
	if params.HealthCheck.HTTPHealthCheck.Path != "" {
		healthcheckTimeout, err := time.ParseDuration(params.HealthCheck.Timeout)
		if err != nil {
			healthcheckTimeout = 30 * time.Second
		}

		healthcheckInterval, err := time.ParseDuration(params.HealthCheck.Interval)
		if err != nil {
			healthcheckInterval = 30 * time.Second
		}

		healthCheck := &core.HealthCheck{
			Timeout:            durationpb.New(healthcheckTimeout),
			Interval:           durationpb.New(healthcheckInterval),
			UnhealthyThreshold: &wrappers.UInt32Value{Value: params.HealthCheck.UnhealthyThreshold},
			HealthyThreshold:   &wrappers.UInt32Value{Value: params.HealthCheck.HealthyThreshold},
			HealthChecker: &core.HealthCheck_HttpHealthCheck_{
				HttpHealthCheck: &core.HealthCheck_HttpHealthCheck{
					Path: params.HealthCheck.HTTPHealthCheck.Path,
				},
			},
		}

		// optional parameters
		if params.HealthCheck.UnhealthyInterval != "" {
			if healthCheckUnhealthyInterval, err := time.ParseDuration(params.HealthCheck.UnhealthyInterval); err == nil {
				healthCheck.UnhealthyInterval = durationpb.New(healthCheckUnhealthyInterval)
			}
		}

		healthChecks = append(healthChecks, healthCheck)
		logger.Infof("healthcheck on " + params.HealthCheck.HTTPHealthCheck.Path)
	}

	cluster := &api.Cluster{
		Name: params.Name,
		ClusterDiscoveryType: &api.Cluster_Type{
			Type: api.Cluster_STRICT_DNS,
		},
		ConnectTimeout:  durationpb.New(connectTimeout),
		DnsLookupFamily: api.Cluster_V4_ONLY,
		LbPolicy:        api.Cluster_ROUND_ROBIN,
		HealthChecks:    healthChecks,
		TransportSocket: transportSocket,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: params.Name,
			Endpoints: []*endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: address,
								},
							},
						},
					},
				},
			},
		},
	}

	// HTTP2 support
	if params.HTTP2 {
		typedExtensionProtocolOptions := &upstreams.HttpProtocolOptions{
			UpstreamProtocolOptions: &upstreams.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &upstreams.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &upstreams.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &core.Http2ProtocolOptions{
							ConnectionKeepalive: &core.KeepaliveSettings{
								Interval: &durationpb.Duration{
									Seconds: 30,
								},
								Timeout: &durationpb.Duration{
									Seconds: 5,
								},
							},
						},
					},
				},
			},
		}
		typedExtensionProtocolOptionsEncoded, err := anypb.New(typedExtensionProtocolOptions)
		if err != nil {
			panic(err)
		}
		cluster.TypedExtensionProtocolOptions = make(map[string]*anypb.Any)
		cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"] = typedExtensionProtocolOptionsEncoded
	}

	return cluster

}

func (c *Cluster) GetClusterNames(clusters []cacheTypes.Resource) []string {
	var clusterNames []string
	for _, v := range clusters {
		clusterNames = append(clusterNames, v.(*api.Cluster).Name)
	}
	return clusterNames
}
func (c *Cluster) PrintCluster(cache *WorkQueueCache, name string) (string, error) {
	clusterFound := false
	out := ""
	for _, v := range cache.clusters {
		cluster := v.(*api.Cluster)
		if cluster.Name == name {
			clusterFound = true
			out += "Name: " + cluster.GetName()
			healthChecks := cluster.GetHealthChecks()
			for _, v := range healthChecks {

				out += "\nHealthCheck: " + v.GetHttpHealthCheck().GetPath()
				out += " - " + v.GetHealthyThreshold().String()
				out += " - " + v.GetUnhealthyThreshold().String()
				out += " - " + v.GetInterval().String()
				out += " - " + v.GetTimeout().String()
				out += " - " + v.GetUnhealthyInterval().String()
			}
		}
	}
	if clusterFound {
		return out, nil
	}
	return out, fmt.Errorf("Cluster not found")
}

func (c *Cluster) updateDefaults(clusters []cacheTypes.Resource, params DefaultsParams) error {
	c.DefaultsParams.ConnectTimeout = params.ConnectTimeout
	for k := range clusters {
		cluster := clusters[k].(*api.Cluster)
		if cluster.ConnectTimeout.Seconds == PRESET_CONNECT_TIMEOUT_SECONDS {
			cluster.ConnectTimeout = durationpb.New((time.Duration(c.DefaultsParams.ConnectTimeout) * time.Second))
			clusters[k] = cluster
		}
	}
	return nil
}
