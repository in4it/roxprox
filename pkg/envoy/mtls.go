package envoy

import (
	"fmt"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type MTLS struct {
	enabled bool
}

func newMTLS() *MTLS {
	return &MTLS{}
}

func (l *MTLS) updateMTLSListener(cache *WorkQueueCache, params ListenerParams, paramsTLS TLSParams, mTLSParams MTLSParams) error {
	_, _, _, listenerName, _, _ := getListenerAttributes(params, paramsTLS)
	listenerIndex := getListenerIndex(cache.listeners, listenerName)
	if listenerIndex == -1 {
		return fmt.Errorf("Listener not found: %s", listenerName)
	}
	ll := cache.listeners[listenerIndex].(*api.Listener)
	ll.ListenerFilters = []*api.ListenerFilter{
		{
			Name: "envoy.listener.tls_inspector",
		},
	}
	matchSubjectAltNames := make([]*matcher.StringMatcher, len(mTLSParams.AllowedSubjectAltNames))
	for k, name := range mTLSParams.AllowedSubjectAltNames {
		matchSubjectAltNames[k] = &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Exact{
				Exact: name,
			},
		}
	}
	if len(mTLSParams.AllowedSubjectAltNames) == 0 {
		matchSubjectAltNames = nil
	}
	// add cert and key to tls listener
	tlsContext, err := ptypes.MarshalAny(&tls.DownstreamTlsContext{
		RequireClientCertificate: &wrapperspb.BoolValue{
			Value: true,
		},
		CommonTlsContext: &tls.CommonTlsContext{
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
					MatchSubjectAltNames: matchSubjectAltNames,
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
		Name: "tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: tlsContext,
		},
	}

	return nil
}
