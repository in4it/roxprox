package api

type JwtProvider struct {
	API      string          `json:"api" yaml:"api"`
	Kind     string          `json:"kind" yaml:"kind"`
	Metadata Metadata        `json:"metadata" yaml:"metadata"`
	Spec     JwtProviderSpec `json:"spec" yaml:"spec"`
}
type JwtProviderSpec struct {
	Issuer     string `json:"issuer" yaml:"issuer"`
	Forward    bool   `json:"forward" yaml:"forward"`
	RemoteJwks string `json:"remoteJwks" yaml:"remoteJwks"`
}
