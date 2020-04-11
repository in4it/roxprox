package envoy

import (
	"fmt"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	api "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Cluster struct{}

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
		tlsContext, err := ptypes.MarshalAny(&auth.UpstreamTlsContext{
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

	connectTimeout := 2 * time.Second

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
			Timeout:            ptypes.DurationProto(healthcheckTimeout),
			Interval:           ptypes.DurationProto(healthcheckInterval),
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
				healthCheck.UnhealthyInterval = ptypes.DurationProto(healthCheckUnhealthyInterval)
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
		ConnectTimeout:  ptypes.DurationProto(connectTimeout),
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
		cluster.Http2ProtocolOptions = &core.Http2ProtocolOptions{}
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
