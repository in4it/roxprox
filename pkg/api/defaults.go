package api

type Defaults struct {
	API      string       `json:"api" yaml:"api"`
	Kind     string       `json:"kind" yaml:"kind"`
	Metadata Metadata     `json:"metadata" yaml:"metadata"`
	Spec     DefaultsSpec `json:"spec" yaml:"spec"`
}
type DefaultsSpec struct {
	ConnectTimeout int64 `json:"connectTimeout" yaml:"connectTimeout"`
}
