package envoy

import (
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
)

type WorkQueueItem struct {
	id                    string
	Action                string
	DependsOn             string
	DependsOnItemIDs      []string
	TLSParams             TLSParams
	ClusterParams         ClusterParams
	ListenerParams        ListenerParams
	ChallengeParams       ChallengeParams
	CreateCertParams      CreateCertParams
	TracingParams         TracingParams
	CompressionParams     CompressionParams
	AccessLogServerParams AccessLogServerParams
	RateLimitParams       RateLimitParams
	MTLSParams            MTLSParams
	LuaFilterParams       LuaFilterParams
	DefaultsParams        DefaultsParams
	state                 string
}

type WorkQueueCache struct {
	snapshotCache cache.SnapshotCache
	clusters      []cacheTypes.Resource
	listeners     []cacheTypes.Resource
	version       int64
}

type WorkQueueSubmissionState struct {
	id     string
	state  string
	itemID string
}
type TLSParams struct {
	Name       string
	CertBundle string
	PrivateKey string
	Domain     string
}
type ClusterParams struct {
	Name           string
	TargetHostname string
	Port           int64
	HTTP2          bool
	HealthCheck    HealthCheck
	ConnectTimeout int64
}
type ListenerParams struct {
	Name             string
	Protocol         string
	TargetHostname   string
	EnableWebSockets bool
	PrefixRewrite    string
	RegexRewrite     RegexRewrite
	Conditions       Conditions
	Auth             Auth
	Authz            Authz
	DirectResponse   DirectResponse
	Listener         ListenerParamsListener
}

type ListenerParamsListener struct {
	MTLS             string
	Port             int64
	StripAnyHostPort bool
}

type ChallengeParams struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	URI      string `json:"uri"`
	Token    string `json:"token"`
	Body     string `json:"body"`
	AuthzURI string `json:"authzURI"`
}
type CreateCertParams struct {
	Name            string
	Domains         []string
	DomainsToVerify []string
}
type Conditions struct {
	Hostname string
	Prefix   string
	Path     string
	Regex    string
	Methods  []string
}
type Auth struct {
	JwtProvider string
	Issuer      string
	Forward     bool
	RemoteJwks  string
	Listener    ListenerParamsListener
}

type Action struct {
	RuleName       string
	Type           string
	Proxy          ActionProxy
	DirectResponse DirectResponseAction
}

type ActionProxy struct {
	TargetHostname   string
	Port             int64
	HealthCheck      HealthCheck
	EnableWebsockets bool
	PrefixRewrite    string
	RegexRewrite     RegexRewrite
	ConnectTimeout   int64
}

type RegexRewrite struct {
	Regex        string
	Substitution string
}

type HealthCheck struct {
	HTTPHealthCheck    HTTPHealthCheck
	Timeout            string
	Interval           string
	HealthyThreshold   uint32
	UnhealthyThreshold uint32
	UnhealthyInterval  string
}
type HTTPHealthCheck struct {
	Path string
}

type ObjectDependency struct {
	Type string
	Name string
}
type Authz struct {
	Timeout          string
	FailureModeAllow bool
}

type TracingParams struct {
	Enabled          bool
	ClientSampling   float64
	RandomSampling   float64
	OverallSampling  float64
	Listener         ListenerParamsListener
	CollectorCluster string
	ProviderName     string
}

type CompressionParams struct {
	Type                string
	ContentLength       uint32
	ContentType         []string
	DisableOnEtagHeader bool
	Listener            ListenerParamsListener
}

type AccessLogServerParams struct {
	Name                           string
	AdditionalRequestHeadersToLog  []string
	AdditionalResponseHeadersToLog []string
	Listener                       ListenerParamsListener
}

type DirectResponse struct {
	Status uint32
	Body   string
}
type DirectResponseAction struct {
	Status uint32
	Body   string
}

type RateLimitParams struct {
	Name        string
	Descriptors []RateLimitDescriptor
	Listener    ListenerParamsListener
}

type RateLimitDescriptor struct {
	DestinationCluster bool
	SourceCluster      bool
	RemoteAddress      bool
	RequestHeader      string
}

type MTLSParams struct {
	Name                   string
	PrivateKey             string
	Certificate            string
	Port                   int64
	AllowedSubjectAltNames []string
	AllowedIPRanges        []string
	CACertificate          string
	EnableProxyProtocol    bool
}

type LuaFilterParams struct {
	Name       string
	InlineCode string
	Listener   ListenerParamsListener
}

type DefaultsParams struct {
	Name           string
	ConnectTimeout int64
}
