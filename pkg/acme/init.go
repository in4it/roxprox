package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/juju/loggo"
	"golang.org/x/crypto/acme"
)

var logger = loggo.GetLogger("acme")

type Acme struct {
	config     Config
	client     *acme.Client
	challenges map[string]*acme.Challenge
}
type Config struct {
	AccountKey *rsa.PrivateKey
	Contact    string
}

func NewAcme(config Config) *Acme {
	return &Acme{
		config:     config,
		client:     &acme.Client{Key: config.AccountKey},
		challenges: make(map[string]*acme.Challenge),
	}
}

func (a *Acme) Register() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	account := &acme.Account{Contact: []string{"mailto: " + a.config.Contact}}
	resp, err := a.client.Register(ctx, account, acme.AcceptTOS)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// StautsConflict = already registered
		err = nil
	}
	if err != nil {
		logger.Debugf("Register failed: %s", err)
	} else {
		logger.Debugf("Register successful: response: %+v", resp)
	}

	return err
}

func (a *Acme) AuthorizeUsingHttp(domain string) (string, string, string, string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	authorization, err := a.client.Authorize(ctx, domain)
	if err != nil {
		return "", "", "", "", false, err
	}

	logger.Debugf("Authorization for %s: %+v", domain, authorization)

	switch authorization.Status {
	case acme.StatusValid:
		return "", "", "", "", true, nil
	case acme.StatusInvalid:
		return "", "", "", "", false, fmt.Errorf("Invalid authorization %q", authorization.URI)
	}

	for _, challenge := range authorization.Challenges {
		if challenge.Type == "http-01" {
			path := a.client.HTTP01ChallengePath(challenge.Token)
			response, err := a.client.HTTP01ChallengeResponse(challenge.Token)
			if err != nil {
				return "", "", "", "", false, err
			}
			// save challenge
			a.challenges[domain] = challenge
			// return challenge info
			return authorization.URI, path, challenge.Token, response, false, nil
		}
	}
	return "", "", "", "", false, errors.New("Authorization doesn't include http-01 challenge")
}

func (a *Acme) AuthorizeUsingHttpAccept(domain string) error {
	if challenge, ok := a.challenges[domain]; ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		_, err := a.client.Accept(ctx, challenge)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Cannot accept challenge: challenge not found for domain %s", domain)
	}
	return nil
}

func (a *Acme) WaitForAuthz(domain, uri string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, err := a.client.WaitAuthorization(ctx, uri)
	if err != nil {
		return false, err
	}
	return true, nil
}
func (a *Acme) CreateCert(csr []byte) ([][]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return a.client.CreateCert(ctx, csr, 0, true)
}
func (a *Acme) CreateCSR(domains []string, key *rsa.PrivateKey) ([]byte, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: domains[0]},
		DNSNames:        domains[1:],
		ExtraExtensions: []pkix.Extension{},
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

func (a *Acme) GetLeafAndValidateCert(domain string, der [][]byte, key *rsa.PrivateKey) (leaf *x509.Certificate, bundle []*x509.Certificate, err error) {
	return validCert(domain, der, key, time.Now())
}
