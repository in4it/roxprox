package api

type JwtProvider struct {
	API      string   `json:"api"`
	Kind     string   `json:"kind"`
	Metadata Metadata `json:"metadata"`
	Spec     JwtProviderSpec `json:"spec"`
}
type JwtProviderSpec struct {
	Issuer string           `json:"issuer"`
	Forward bool `json:"forward"`
	RemoteJwks string `json:"remote_jwks"`
}
