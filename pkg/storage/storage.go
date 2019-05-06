package storage

import (
	"crypto/rsa"

	"github.com/in4it/envoy-autocert/pkg/api"
	"github.com/in4it/envoy-autocert/pkg/storage/local"
	"github.com/in4it/envoy-autocert/pkg/storage/s3"
)

type Config struct {
	path string
}

type Storage interface {
	GetError(name string) error
	ListRules() ([]api.Rule, error)
	GetRule(name string) (api.Rule, error)
	ListCerts() (map[string]string, error)
	GetCert(name string) (string, error)
	GetCertBundle(name string) (string, error)
	WriteCert(name string, cert []byte) error
	WriteCertBundle(name string, certs []byte) error
	GetPrivateAccountkey() (*rsa.PrivateKey, error)
	GetPublicAccountkey() (*rsa.PublicKey, error)
	CreateAccountKey() error
	CreateKey(name string) error
	GetPrivateKey(name string) (*rsa.PrivateKey, error)
	GetPrivateKeyPem(name string) (string, error)
	WriteChallenge(name string, data []byte) error
}

func NewStorage(t string, config interface{}) Storage {
	var storage Storage
	if t == "local" {
		storage = local.NewLocalStorage(config.(local.Config))
	} else if t == "s3" {
		storage = s3.NewS3Storage(config.(s3.Config))
	}
	return storage
}
