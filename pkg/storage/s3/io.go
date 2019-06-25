package s3

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/in4it/roxprox/pkg/api"
	"github.com/in4it/roxprox/pkg/crypto"
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
	cache  map[string]string
}

func NewS3Storage(config Config) (*S3Storage, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(config.Region)})
	if err != nil {
		logger.Errorf("Couldn't initialize S3: %s", err)
		return nil, nil
	}
	svc := s3.New(sess)

	// test connection
	input := &s3.GetObjectInput{
		Bucket: aws.String(config.Bucket),
		Key:    aws.String(config.Prefix + "/test-perms"),
	}
	_, err = svc.GetObject(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchKey:
				// we have s3 permissions
			default:
				return nil, aerr
			}
		} else {
			return nil, err
		}
	}

	notifications := newNotifications(config)
	notifications.StartQueue()

	return &S3Storage{config: config, svc: svc, sess: sess, cache: make(map[string]string)}, nil
}

func (s *S3Storage) GetError(name string) error {
	if name == "errNotExist" {
		return errNotExist
	}
	return nil
}
func (s *S3Storage) ListObjects() ([]api.Object, error) {
	var (
		objects []api.Object
		err     error
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
					object, err := s.GetObject(aws.StringValue(item.Key))
					if err != nil {
						logger.Errorf("error while getting rule: %s", err)
					}
					objects = append(objects, object)
				}

			}
			return pageNum <= 1000
		})

	if err != nil {
		return objects, err
	}
	return objects, nil
}
func (s *S3Storage) GetObject(name string) (api.Object, error) {
	var object api.Object
	contents := aws.NewWriteAtBuffer([]byte{})
	filename := s.config.Prefix + "/" + name
	downloader := s3manager.NewDownloader(s.sess)
	_, err := downloader.Download(contents,
		&s3.GetObjectInput{
			Bucket: aws.String(s.config.Bucket),
			Key:    aws.String(filename),
		})
	if err != nil {
		return object, err
	}
	err = yaml.Unmarshal(contents.Bytes(), &object)
	if err != nil {
		return object, err
	}
	switch object.Kind {
	case "rule":
		var rule api.Rule
		err = yaml.Unmarshal(contents.Bytes(), &rule)
		if err != nil {
			return object, err
		}
		object.Data = rule
	case "jwtProvider":
		var jwtProvider api.JwtProvider
		err = yaml.Unmarshal(contents.Bytes(), &jwtProvider)
		if err != nil {
			return object, err
		}
		object.Data = jwtProvider
	default:
		return object, errors.New("Object in wrong format")
	}
	// keep a cache of filename -> rule name matching
	s.cache[filename] = object.Metadata.Name
	return object, nil

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

func (s *S3Storage) GetCachedRuleName(filename string) (string, error) {
	if s.config.Prefix == "" {
		filename = "/" + filename
	}
	if val, ok := s.cache[filename]; ok {
		return val, nil
	}

	return "", fmt.Errorf("Filename %s not found in cache", filename)
}
