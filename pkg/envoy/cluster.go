package envoy

import (
	"fmt"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/endpoint"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
)

type Cluster struct{}

func newCluster() *Cluster {
	return &Cluster{}
}

func (c *Cluster) findCluster(clusters []cache.Resource, params ClusterParams) (int, error) {
	for k, v := range clusters {
		if v.(*api.Cluster).Name == params.Name {
			return k, nil
		}
	}
	return -1, fmt.Errorf("Cluster not found")
}
func (c *Cluster) findClusterByName(clusters []cache.Resource, name string) (int, error) {
	for k, v := range clusters {
		if v.(*api.Cluster).Name == name {
			return k, nil
		}
	}
	return -1, fmt.Errorf("Cluster not found")
}

func (c *Cluster) createCluster(params ClusterParams) *api.Cluster {
	var tlsContext *auth.UpstreamTlsContext
	if params.Port == 443 {
		tlsContext = &auth.UpstreamTlsContext{
			Sni: params.TargetHostname,
		}
	}

	logger.Infof("Creating cluster " + params.Name)

	address := &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address:      params.TargetHostname,
			Protocol:     core.TCP,
			ResolverName: "STRICT_DNS",
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: uint32(params.Port),
			},
		},
	}}

	return &api.Cluster{
		Name: params.Name,
		ClusterDiscoveryType: &api.Cluster_Type{
			Type: api.Cluster_STRICT_DNS,
		},
		ConnectTimeout:  2 * time.Second,
		DnsLookupFamily: api.Cluster_V4_ONLY,
		LbPolicy:        api.Cluster_ROUND_ROBIN,
		TlsContext:      tlsContext,
		LoadAssignment: &api.ClusterLoadAssignment{
			ClusterName: params.Name,
			Endpoints: []endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []endpoint.LbEndpoint{
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

}

func (c *Cluster) GetClusterNames(clusters []cache.Resource) []string {
	var clusterNames []string
	for _, v := range clusters {
		clusterNames = append(clusterNames, v.(*api.Cluster).Name)
	}
	return clusterNames
}
