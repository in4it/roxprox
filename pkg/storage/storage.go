package storage

import (
	"crypto/rsa"
	"fmt"

	"github.com/in4it/roxprox/pkg/api"
	"github.com/in4it/roxprox/pkg/storage/local"
	"github.com/in4it/roxprox/pkg/storage/s3"
)

type Config struct {
	path string
}

type Storage interface {
	SetLogLevel(loglevel string)
	SetStoragePath(path string)
	GetError(name string) error
	ListObjects() ([]api.Object, error)
	GetObject(name string) ([]api.Object, error)
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
	GetCachedObjectName(filename string) ([]*api.Object, error)
	DeleteCachedObject(filename string) error
	CountCachedObjectByCondition(condition api.RuleConditions) int
	GetCachedRule(name string) *api.Object
}

func NewStorage(t string, config interface{}) (Storage, error) {
	if t == "local" {
		return local.NewLocalStorage(config.(local.Config))
	} else if t == "s3" {
		return s3.NewS3Storage(config.(s3.Config))
	} else {
		return nil, fmt.Errorf("Unknown storage type supplied")
	}
}
