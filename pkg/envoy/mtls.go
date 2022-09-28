package envoy

import (
	"fmt"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbacConfig "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	proxyProtocol "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"
)

type MTLS struct {
	enabled bool
}

func newMTLS() *MTLS {
	return &MTLS{}
}

func (l *MTLS) updateMTLSListener(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams, mTLSParams MTLSParams) error {
	_, _, _, listenerName, _, _ := getListenerAttributes(params, paramsTLS)

	// validation
	if mTLSParams.CACertificate == "" {
		return fmt.Errorf("Cannot create/update mTLS listener: CA Certificate is empty")
	}
	if mTLSParams.Certificate == "" {
		return fmt.Errorf("Cannot create/update mTLS listener: Server Certificate is empty")
	}
	if mTLSParams.PrivateKey == "" {
		return fmt.Errorf("Cannot create/update mTLS listener: Private Key is empty")
	}
	if mTLSParams.Name == "" {
		return fmt.Errorf("Cannot create/update mTLS listener: mTLS name is empty")
	}

	listenerIndex := getListenerIndex(cache.listeners, listenerName)
	if listenerIndex == -1 {
		return fmt.Errorf("Listener not found: %s", listenerName)
	}
	ll := cache.listeners[listenerIndex].(*api.Listener)
	// set proxy protocol filter
	ll.ListenerFilters = []*api.ListenerFilter{}
	if mTLSParams.EnableProxyProtocol {
		proxyProtocol := &proxyProtocol.ProxyProtocol{}
		proxyProtocolPbst, err := anypb.New(proxyProtocol)
		if err != nil {
			return fmt.Errorf("anypb.New error: %s", err)
		}
		ll.ListenerFilters = append(ll.ListenerFilters, &api.ListenerFilter{
			Name: "envoy.filters.listener.proxy_protocol",
			ConfigType: &api.ListenerFilter_TypedConfig{
				TypedConfig: proxyProtocolPbst,
			},
		})
	}
	// set AllowedIPRanges
	if len(mTLSParams.AllowedIPRanges) > 0 {
		rbacFilter := []*api.Filter{
			{
				Name: "envoy.filters.network.rbac",
				ConfigType: &api.Filter_TypedConfig{
					TypedConfig: getRBACConfig(mTLSParams),
				},
			},
		}
		ll.FilterChains[0].Filters = append(rbacFilter, ll.FilterChains[0].Filters...)
	}
	matchSubjectAltNames := make([]*tls.SubjectAltNameMatcher, len(mTLSParams.AllowedSubjectAltNames))
	for k, name := range mTLSParams.AllowedSubjectAltNames {
		matchSubjectAltNames[k] = &tls.SubjectAltNameMatcher{
			SanType: tls.SubjectAltNameMatcher_DNS,
			Matcher: &matcher.StringMatcher{
				MatchPattern: &matcher.StringMatcher_Exact{
					Exact: name,
				},
			},
		}
	}
	if len(mTLSParams.AllowedSubjectAltNames) == 0 {
		matchSubjectAltNames = nil
	}
	// add cert and key to tls listener
	tlsContext, err := anypb.New(&tls.DownstreamTlsContext{
		RequireClientCertificate: &wrapperspb.BoolValue{
			Value: true,
		},
		CommonTlsContext: &tls.CommonTlsContext{
			TlsParams: &tls.TlsParameters{
				TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
			},
			TlsCertificates: []*tls.TlsCertificate{
				{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: mTLSParams.Certificate,
						},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: mTLSParams.PrivateKey,
						},
					},
				},
			},
			ValidationContextType: &tls.CommonTlsContext_ValidationContext{
				ValidationContext: &tls.CertificateValidationContext{
					MatchTypedSubjectAltNames: matchSubjectAltNames,
					TrustedCa: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: mTLSParams.CACertificate,
						},
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	ll.FilterChains[0].TransportSocket = &core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: tlsContext,
		},
	}

	return nil
}
func getRBACConfig(mTLSParams MTLSParams) *anypb.Any {
	principals := []*rbacConfig.Principal{}
	for _, ipRange := range mTLSParams.AllowedIPRanges {
		ipRangeSplit := strings.Split(ipRange, "/")
		prefixLen, err := strconv.ParseUint(ipRangeSplit[1], 10, 32)
		if len(ipRangeSplit) != 2 || err != nil {
			logger.Warningf("Invalid IP address range: %s in listener: l_mtls_%s", ipRange, mTLSParams.Name)
		} else {
			principals = append(principals, &rbacConfig.Principal{

				Identifier: &rbacConfig.Principal_DirectRemoteIp{
					DirectRemoteIp: &core.CidrRange{
						AddressPrefix: ipRangeSplit[0],
						PrefixLen: &wrappers.UInt32Value{
							Value: uint32(prefixLen),
						},
					},
				},
			})
		}
	}
	r := &rbac.RBAC{
		StatPrefix: "rbac_" + mTLSParams.Name,
		Rules: &rbacConfig.RBAC{
			Action: rbacConfig.RBAC_ALLOW,
			Policies: map[string]*rbacConfig.Policy{
				"ip_filter": {
					Principals: principals,
					Permissions: []*rbacConfig.Permission{
						{
							Rule: &rbacConfig.Permission_Any{
								Any: true,
							},
						},
					},
				},
			},
		},
	}
	pbst, err := anypb.New(r)
	if err != nil {
		panic(err)
	}

	return pbst
}
