package storage

import (
	"crypto/rsa"
	"fmt"
	"strings"

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
	CountCachedObjectByCondition(condition api.RuleConditions, actions []api.RuleActions) int
	CountCachedJwtRulesByCondition(condition api.RuleConditions, jwtProvider string) int
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

func NewLocalStorage(storagePath string) (Storage, error) {
	storage, err := NewStorage("local", local.Config{Path: storagePath})
	if err != nil {
		return nil, fmt.Errorf("Couldn't inialize storage: %s", err)
	}

	return storage, nil
}
func NewS3Storage(storageBucket, storagePath, awsRegion string) (Storage, error) {
	if storageBucket == "" {
		return nil, fmt.Errorf("No bucket specified")
	}
	if strings.HasSuffix(storagePath, "/") {
		storagePath = storagePath[:len(storagePath)-1]
	}
	storage, err := NewStorage("s3", s3.Config{Prefix: storagePath, Bucket: storageBucket, Region: awsRegion})
	if err != nil {
		return nil, fmt.Errorf("Couldn't inialize storage: %s", err)
	}

	return storage, nil
}
