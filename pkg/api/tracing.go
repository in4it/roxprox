package api

type Tracing struct {
	API      string      `json:"api" yaml:"api"`
	Kind     string      `json:"kind" yaml:"kind"`
	Metadata Metadata    `json:"metadata" yaml:"metadata"`
	Spec     TracingSpec `json:"spec" yaml:"spec"`
}
type TracingSpec struct {
	Enabled          bool     `json:"enabled" yaml:"enabled"`
	ClientSampling   float64  `json:"clientSampling" yaml:"clientSampling"`
	RandomSampling   float64  `json:"randomSampling" yaml:"randomSampling"`
	OverallSampling  float64  `json:"overallSampling" yaml:"overallSampling"`
	Listener         Listener `json:"listener"`
	ProviderName     string   `json:"providerName" yaml:"providerName"`
	CollectorCluster string   `json:"collectorCluster" yaml:"collectorCluster"`
}
