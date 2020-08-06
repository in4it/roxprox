package api

type RateLimit struct {
	API      string        `json:"api" yaml:"api"`
	Kind     string        `json:"kind" yaml:"kind"`
	Metadata Metadata      `json:"metadata" yaml:"metadata"`
	Spec     RateLimitSpec `json:"spec" yaml:"spec"`
}
type RateLimitSpec struct {
	Descriptors    []RateLimitDescriptor `json:"descriptors" yaml:"descriptors"`
	RequestPerUnit string                `json:"requestPerUnit" yaml:"requestPerUnit"`
	Unit           string                `json:"unit" yaml:"unit"`
}
type RateLimitDescriptor struct {
	DestinationCluster bool   `json:"destinationCluster" yaml:"destinationCluster"`
	SourceCluster      bool   `json:"sourceCluster" yaml:"sourceCluster"`
	RemoteAddress      bool   `json:"remoteAddress" yaml:"remoteAddress"`
	RequestHeader      string `json:"requestHeader" yaml:"requestHeader"`
}
