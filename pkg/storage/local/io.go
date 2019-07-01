package local

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/in4it/roxprox/pkg/api"
	"github.com/in4it/roxprox/pkg/crypto"
	"github.com/juju/loggo"
	"github.com/google/go-cmp/cmp"
)

var (
	logger      = loggo.GetLogger("storage.local")
	errNotExist = errors.New("File does not exist")
)

type LocalStorage struct {
	config Config
	dir    string
	cache  map[string]*api.Object
}
type Config struct {
	Path string
}

func NewLocalStorage(config Config) (*LocalStorage, error) {
	var dir string

	wd, err := os.Getwd()
	if err == nil {
		dir = wd + "/" + config.Path
	} else {
		dir = config.Path
	}
	return &LocalStorage{config: config, dir: dir, cache: make(map[string]*api.Object)}, nil
}

func (l *LocalStorage) GetError(name string) error {
	if name == "errNotExist" {
		return errNotExist
	}
	return nil
}

/*
 * ListObjects read directory contents and converts contents into rules
 */
func (l *LocalStorage) ListObjects() ([]api.Object, error) {
	var objects []api.Object
	var err error

	logger.Debugf("Reading dir: %s", l.dir)

	files, err := ioutil.ReadDir(l.dir)
	if err != nil {
		return objects, err
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".yaml") || strings.HasSuffix(f.Name(), ".yml") {
			object, err := l.GetObject(f.Name())
			if err != nil {
				return nil, err
			}
			objects = append(objects, object)
		}
	}
	return objects, nil
}

/*
 * GetObject gets a single rule from storage and converts contents into rules
 */
func (l *LocalStorage) GetObject(name string) (api.Object, error) {
	var object api.Object
	logger.Debugf("Parsing file: %s", l.dir+"/"+name)
	contents, err := ioutil.ReadFile(l.dir + "/" + name)
	if err != nil {
		return object, err
	}
	err = yaml.Unmarshal(contents, &object)
	if err != nil {
		return object, err
	}
	switch object.Kind {
	case "rule":
		var rule api.Rule
		err = yaml.Unmarshal(contents, &rule)
		if err != nil {
			return object, err
		}
		object.Data = rule
	case "jwtProvider":
		var jwtProvider api.JwtProvider
		err = yaml.Unmarshal(contents, &jwtProvider)
		if err != nil {
			return object, err
		}
		object.Data = jwtProvider
	default:
		return object, errors.New("Rule in wrong format")
	}
	// keep a cache of filename -> rule name matching
	l.cache[name] = &object
	return object, nil
}
func (l *LocalStorage) ListCerts() (map[string]string, error) {
	dirname := l.dir + "/pki/certs/"
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, err
	}

	certs := make(map[string]string)

	for _, file := range files {
		if strings.HasSuffix(file.Name(), "-bundle.crt") {
			certName := strings.Replace(file.Name(), "-bundle.crt", "", -1)
			cert, err := l.GetCert(certName)
			if err != nil {
				return nil, err
			}
			certs[certName] = cert
		}
	}
	return certs, nil
}
func (l *LocalStorage) GetCert(name string) (string, error) {
	filename := l.dir + "/pki/certs/" + name + ".crt"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return "", errNotExist
	}
	contents, err := ioutil.ReadFile(filename)
	return string(contents), err
}
func (l *LocalStorage) GetCertBundle(name string) (string, error) {
	filename := l.dir + "/pki/certs/" + name + "-bundle.crt"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return "", errNotExist
	}
	contents, err := ioutil.ReadFile(filename)
	return string(contents), err
}

func (l *LocalStorage) WriteCert(name string, cert []byte) error {
	filename := l.dir + "/pki/certs/" + name + ".crt"
	if _, err := os.Stat(l.dir + "/pki/certs"); os.IsNotExist(err) {
		err = os.MkdirAll(l.dir+"/pki/certs", 0755)
		if err != nil {
			return err
		}
	}

	logger.Debugf("writing certundle: %s", filename)
	return ioutil.WriteFile(filename, cert, 0644)
}
func (l *LocalStorage) WriteCertBundle(name string, certs []byte) error {
	filename := l.dir + "/pki/certs/" + name + "-bundle.crt"
	if _, err := os.Stat(l.dir + "/pki/certs"); os.IsNotExist(err) {
		err = os.MkdirAll(l.dir+"/pki/certs", 0755)
		if err != nil {
			return err
		}
	}

	logger.Debugf("writing cert bundle: %s", filename)
	return ioutil.WriteFile(filename, certs, 0644)
}
func (l *LocalStorage) GetPrivateAccountkey() (*rsa.PrivateKey, error) {
	filename := l.dir + "/pki/accountkeys/private.pem"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, errNotExist
	}
	privateKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return crypto.GetPrivateKey(privateKey)
}
func (l *LocalStorage) GetPublicAccountkey() (*rsa.PublicKey, error) {
	filename := l.dir + "/pki/accountkeys/public.pem"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, errNotExist
	}
	publicKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return crypto.GetPublicKey(publicKey)
}
func (l *LocalStorage) CreateAccountKey() error {
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}

	if _, err := os.Stat(l.dir + "/pki/accountkeys"); os.IsNotExist(err) {
		err = os.MkdirAll(l.dir+"/pki/accountkeys", 0755)
		if err != nil {
			return err
		}
	}

	err = crypto.SavePEMKey(l.dir+"/pki/accountkeys/private.pem", key)
	if err != nil {
		return err
	}

	err = crypto.SavePublicPEMKey(l.dir+"/pki/accountkeys/public.pem", key.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

func (l *LocalStorage) WriteChallenge(name string, data []byte) error {
	if _, err := os.Stat(l.dir + "/challenges"); os.IsNotExist(err) {
		err = os.MkdirAll(l.dir+"/challenges", 0755)
		if err != nil {
			return err
		}
	}
	return ioutil.WriteFile(l.dir+"/challenges/"+name+".json", data, 0644)
}
func (l *LocalStorage) CreateKey(name string) error {
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}

	if _, err := os.Stat(l.dir + "/pki/keys"); os.IsNotExist(err) {
		err = os.MkdirAll(l.dir+"/pki/keys", 0755)
		if err != nil {
			return err
		}
	}

	err = crypto.SavePEMKey(l.dir+"/pki/keys/"+name+".pem", key)
	if err != nil {
		return err
	}

	err = crypto.SavePublicPEMKey(l.dir+"/pki/keys/"+name+"-public.pem", key.PublicKey)
	if err != nil {
		return err
	}

	return nil
}
func (l *LocalStorage) GetPrivateKey(name string) (*rsa.PrivateKey, error) {
	filename := l.dir + "/pki/keys/" + name + ".pem"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, errNotExist
	}
	privateKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return crypto.GetPrivateKey(privateKey)
}
func (l *LocalStorage) GetPrivateKeyPem(name string) (string, error) {
	filename := l.dir + "/pki/keys/" + name + ".pem"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return "", errNotExist
	}
	privateKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(privateKey), nil
}

func (l *LocalStorage) GetCachedObjectName(filename string) (*api.Object, error) {
	if val, ok := l.cache[filename]; ok {
		return val, nil
	}

	return nil, fmt.Errorf("Filename %s not found in cache", filename)
}
func (l *LocalStorage) DeleteCachedObject(filename string) error {
	if _, ok := l.cache[filename]; ok {
		delete(l.cache, filename)
		return nil
	}

	return fmt.Errorf("Filename %s not found in cache", filename)
}
func (l *LocalStorage) CountCachedObjectByCondition(condition api.RuleConditions) int {
	count := 0
	for _, object := range l.cache {
		if object.Kind == "rule" {
			rule := object.Data.(api.Rule)
			if conditionExists(rule.Spec.Conditions, condition) {
				count++
			}
		}
	}
	return count
}
func conditionExists(conditions []api.RuleConditions, condition api.RuleConditions) bool {
	for _, v := range conditions {
		if cmp.Equal(v, condition) {
			return true
		}
	}
	return false
}