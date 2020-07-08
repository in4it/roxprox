package envoy

import (
	cacheTypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
)

type WorkQueueItem struct {
	id               string
	Action           string
	DependsOn        string
	DependsOnItemIDs []string
	TLSParams        TLSParams
	ClusterParams    ClusterParams
	ListenerParams   ListenerParams
	ChallengeParams  ChallengeParams
	CreateCertParams CreateCertParams
	TracingParams    TracingParams
	state            string
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
}
type ListenerParams struct {
	Name             string
	Protocol         string
	TargetHostname   string
	EnableWebSockets bool
	Conditions       Conditions
	Auth             Auth
	Authz            Authz
	DirectResponse   DirectResponse
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
	Enabled         bool
	ClientSampling  float64
	RandomSampling  float64
	OverallSampling float64
}

type DirectResponse struct {
	Status uint32
	Body   string
}
type DirectResponseAction struct {
	Status uint32
	Body   string
}
