package api

type AuthzFilter struct {
	API      string          `json:"api" yaml:"api"`
	Kind     string          `json:"kind" yaml:"kind"`
	Metadata Metadata        `json:"metadata" yaml:"metadata"`
	Spec     AuthzFilterSpec `json:"spec" yaml:"spec"`
}
type AuthzFilterSpec struct {
	ClusterName      string `json:"clusterName" yaml:"clusterName"`
	FailureModeAllow bool   `json:"failureModeAllow" yaml:"failureModeAllow"`
	Timeout          string `json:"timeout" yaml:"timeout"`
	Hostname         string `json:"hostname" yaml:"hostname"`
	Port             int64  `json:"port" yaml:"port"`
}
