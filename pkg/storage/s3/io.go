package s3

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/in4it/envoy-autocert/pkg/api"
	"github.com/in4it/envoy-autocert/pkg/crypto"
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
	var (
		rules []api.Rule
		err   error
	)

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.config.Bucket),
	}
	pageNum := 0
	err = s.svc.ListObjectsV2Pages(input,
		func(page *s3.ListObjectsV2Output, lastPage bool) bool {
			pageNum++
			for _, item := range page.Contents {
				if strings.HasSuffix(aws.StringValue(item.Key), ".yaml") || strings.HasSuffix(aws.StringValue(item.Key), ".yml") {
					rule, err := s.GetRule(aws.StringValue(item.Key))
					if err != nil {
						logger.Errorf("error while getting rule: %s", err)
					}
					rules = append(rules, rule)
				}

			}
			return pageNum <= 1000
		})

	if err != nil {
		return rules, err
	}
	return rules, nil
}
func (s *S3Storage) GetRule(name string) (api.Rule, error) {
	var object api.Object
	var rule api.Rule
	contents := aws.NewWriteAtBuffer([]byte{})
	filename := s.config.Prefix + "/" + name
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(contents,
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
	var err error
	certs := make(map[string]string)

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.config.Bucket),
		Prefix: aws.String("/pki/certs/"),
	}
	pageNum := 0
	err = s.svc.ListObjectsV2Pages(input,
		func(page *s3.ListObjectsV2Output, lastPage bool) bool {
			pageNum++
			for _, item := range page.Contents {
				if strings.HasSuffix(aws.StringValue(item.Key), "-bundle.crt") {
					var cert string
					certName := strings.Replace(aws.StringValue(item.Key), "-bundle.crt", "", -1)
					cert, err = s.GetCert(certName)
					if err != nil {
						logger.Errorf("error while getting cert: %s", err)
					}
					certs[certName] = cert
				}
			}
			return pageNum <= 1000
		})

	if err != nil {
		return certs, err
	}
	return certs, nil
}
func (s *S3Storage) GetCert(name string) (string, error) {
	contents := aws.NewWriteAtBuffer([]byte{})
	filename := s.config.Prefix + "/pki/certs/" + name + ".crt"
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(contents,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(filename),
		})
	if err != nil {
		return "", nil
	}
	return string(contents.Bytes()), nil
}
func (s *S3Storage) GetCertBundle(name string) (string, error) {
	contents := aws.NewWriteAtBuffer([]byte{})
	filename := s.config.Prefix + "/pki/certs/" + name + "-bundle.crt"
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(contents,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(filename),
		})
	if err != nil {
		return "", nil
	}
	return string(contents.Bytes()), nil
}
func (s *S3Storage) WriteCert(name string, cert []byte) error {
	key := s.config.Prefix + "/pki/certs/" + name + ".crt"

	uploader := s3manager.NewUploader(s.sess)

	logger.Debugf("Uploading %s to S3...", key)

	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.config.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(cert),
	})
	if err != nil {
		return err
	}

	return nil
}
func (s *S3Storage) WriteCertBundle(name string, certs []byte) error {
	key := s.config.Prefix + "/pki/certs/" + name + "-bundle.crt"

	uploader := s3manager.NewUploader(s.sess)

	logger.Debugf("Uploading %s to S3...", key)

	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.config.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(certs),
	})
	if err != nil {
		return err
	}

	return nil
}
func (s *S3Storage) GetPrivateAccountkey() (*rsa.PrivateKey, error) {
	privateKey := aws.NewWriteAtBuffer([]byte{})
	key := s.config.Prefix + "/pki/accountkeys/private.pem"
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(privateKey,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return nil, nil
	}

	return crypto.GetPrivateKey(privateKey.Bytes())
}
func (s *S3Storage) GetPublicAccountkey() (*rsa.PublicKey, error) {
	publicKey := aws.NewWriteAtBuffer([]byte{})
	key := s.config.Prefix + "/pki/accountkeys/public.pem"
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(publicKey,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return nil, nil
	}

	return crypto.GetPublicKey(publicKey.Bytes())
}
func (s *S3Storage) CreateAccountKey() error {
	return s.createKey("/pki/accountkeys/private.pem", "/pki/accountkeys/public.pem")
}
func (s *S3Storage) CreateKey(name string) error {
	return s.createKey("/pki/keys/"+name+".pem", "/pki/keys/"+name+"-public.pem")

}
func (s *S3Storage) GetPrivateKey(name string) (*rsa.PrivateKey, error) {
	privateKey := aws.NewWriteAtBuffer([]byte{})
	key := s.config.Prefix + "/pki/keys/" + name + ".pem"
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(privateKey,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return nil, err
	}

	return crypto.GetPrivateKey(privateKey.Bytes())
}
func (s *S3Storage) GetPrivateKeyPem(name string) (string, error) {
	privateKey := aws.NewWriteAtBuffer([]byte{})
	key := s.config.Prefix + "/pki/keys/" + name + ".pem"
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(privateKey,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return "", err
	}

	return string(privateKey.Bytes()), nil

}
func (s *S3Storage) WriteChallenge(name string, data []byte) error {
	key := s.config.Prefix + "/challenges/" + name + ".json"

	uploader := s3manager.NewUploader(s.sess)

	logger.Debugf("Uploading %s to S3...", key)

	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.config.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return err
	}

	return nil
}
func (s *S3Storage) createKey(privateKeyPath, publicKeyPath string) error {
	rsaKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	privateKey := crypto.ConvertToPEMKey(rsaKey)
	publicKey, err := crypto.ConvertToPublicPEMKey(rsaKey.PublicKey)
	if err != nil {
		return err
	}

	// write private key
	key := s.config.Prefix + privateKeyPath

	uploader := s3manager.NewUploader(s.sess)

	logger.Debugf("Uploading %s to S3...", key)

	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.config.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(privateKey),
	})
	if err != nil {
		return err
	}

	// write public key
	key = s.config.Prefix + publicKeyPath

	logger.Debugf("Uploading %s to S3...", key)

	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s.config.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(publicKey),
	})
	if err != nil {
		return err
	}

	return nil
}
