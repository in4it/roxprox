package api

type MTLS struct {
	API      string   `json:"api" yaml:"api"`
	Kind     string   `json:"kind" yaml:"kind"`
	Metadata Metadata `json:"metadata" yaml:"metadata"`
	Spec     MTLSSpec `json:"spec" yaml:"spec"`
}
type MTLSSpec struct {
	EnableProxyProtocol    bool     `json:"enableProxyProtocol" yaml:"enableProxyProtocol"`
	Certificate            string   `json:"certificate" yaml:"certificate"`
	PrivateKey             string   `json:"privateKey" yaml:"privateKey"`
	CACertificate          string   `json:"caCertificate" yaml:"caCertificate"`
	Port                   int64    `json:"port" yaml:"port"`
	AllowedSubjectAltNames []string `json:"allowedSubjectAltNames" yaml:"allowedSubjectAltNames"`
	AllowedIPRanges        []string `json:"allowedIPRanges" yaml:"allowedIPRanges"`
}
