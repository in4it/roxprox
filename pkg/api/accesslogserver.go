package api

type AccessLogServer struct {
	API      string              `json:"api" yaml:"api"`
	Kind     string              `json:"kind" yaml:"kind"`
	Metadata Metadata            `json:"metadata" yaml:"metadata"`
	Spec     AccessLogServerSpec `json:"spec" yaml:"spec"`
}
type AccessLogServerSpec struct {
	Address                        string   `json:"address" yaml:"address"`
	Port                           int64    `json:"port" yaml:"port"`
	AdditionalRequestHeadersToLog  []string `json:"additionalRequestHeadersToLog" yaml:"additionalRequestHeadersToLog"`
	AdditionalResponseHeadersToLog []string `json:"additionalResponseHeadersToLog" yaml:"additionalResponseHeadersToLog"`
}
