package s3

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/in4it/envoy-autocert/pkg/api"
	"github.com/juju/loggo"
	"gopkg.in/yaml.v2"
)

var (
	logger      = loggo.GetLogger("storage.s3")
	errNotExist = errors.New("File does not exist")
)

type S3Storage struct {
	config Config
	svc    *s3.S3
	sess   *session.Session
}
type Config struct {
	Prefix string
	Bucket string
}

func NewS3Storage(config Config) *S3Storage {
	sess, err := session.NewSession()
	if err != nil {
		logger.Errorf("Couldn't initialize S3: %s", err)
		return nil
	}
	svc := s3.New(sess)

	return &S3Storage{config: config, svc: svc, sess: sess}
}

func (s *S3Storage) GetError(name string) error {
	if name == "errNotExist" {
		return errNotExist
	}
	return nil
}
func (s *S3Storage) ListRules() ([]api.Rule, error) {
	var rules []api.Rule
	resp, err := s.svc.ListObjects(&s3.ListObjectsInput{Bucket: aws.String(s.config.Bucket)})
	if err != nil {
		return rules, fmt.Errorf("Unable to list items in bucket %q, %v", s.config.Bucket, err)
	}

	for _, item := range resp.Contents {
		if strings.HasSuffix(aws.StringValue(item.Key), ".yaml") || strings.HasSuffix(aws.StringValue(item.Key), ".yml") {
			rule, err := s.GetRule(aws.StringValue(item.Key))
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}

	}
	return rules, nil
}
func (s *S3Storage) GetRule(name string) (api.Rule, error) {
	var object api.Object
	var rule api.Rule
	contents := aws.NewWriteAtBuffer([]byte{})
	filename := s.config.Prefix + "/" + name
	downloader := s3manager.NewDownloader(s.sess)
	numBytes, err := downloader.Download(contents,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(filename),
		})
	if err != nil {
		return rule, nil
	}
	err = yaml.Unmarshal(contents.Bytes(), &object)
	if err != nil {
		return rule, err
	}
	if object.Kind == "rule" {
		err = yaml.Unmarshal(contents.Bytes(), &rule)
		if err != nil {
			return rule, err
		}
		return rule, nil
	}
	return rule, errors.New("Rule in wrong format")
}
func (s *S3Storage) ListCerts() (map[string]string, error) {

}
func (s *S3Storage) GetCert(name string) (string, error) {

}
func (s *S3Storage) GetCertBundle(name string) (string, error) {

}
func (s *S3Storage) WriteCert(name string, cert []byte) error {

}
func (s *S3Storage) WriteCertBundle(name string, certs []byte) error {

}
func (s *S3Storage) GetPrivateAccountkey() (*rsa.PrivateKey, error) {

}
func (s *S3Storage) GetPublicAccountkey() (*rsa.PublicKey, error) {

}
func (s *S3Storage) CreateAccountKey() error {

}
func (s *S3Storage) CreateKey(name string) error {

}
func (s *S3Storage) GetPrivateKey(name string) (*rsa.PrivateKey, error) {

}
func (s *S3Storage) GetPrivateKeyPem(name string) (string, error) {

}
func (s *S3Storage) WriteChallenge(name string, data []byte) error {

}
