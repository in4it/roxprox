package api

type MTLS struct {
	API      string   `json:"api" yaml:"api"`
	Kind     string   `json:"kind" yaml:"kind"`
	Metadata Metadata `json:"metadata" yaml:"metadata"`
	Spec     MTLSSpec `json:"spec" yaml:"spec"`
}
type MTLSSpec struct {
	Certificate string `json:"certificate" yaml:"certificate"`
	PrivateKey  string `json:"privateKey" yaml:"unprivateKeyit"`
	Port        int64  `json:"port" yaml:"port"`
}
