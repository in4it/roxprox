package envoy

import (
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"strings"

	acme "github.com/in4it/roxprox/pkg/acme"
	storage "github.com/in4it/roxprox/pkg/storage"
)

type Cert struct {
	a *acme.Acme
	s storage.Storage
}

func newCert(s storage.Storage, acmeContact string) (*Cert, error) {
	c := &Cert{s: s}
	logger.Debugf("Initializing acme")
	accountKey, err := c.s.GetPrivateAccountkey()
	if err == c.s.GetError("errNotExist") {
		err = c.s.CreateAccountKey()
		if err != nil {
			return c, err
		}
		accountKey, err = c.s.GetPrivateAccountkey()
		if err != nil {
			return c, err
		}
		c.a = acme.NewAcme(acme.Config{AccountKey: accountKey, Contact: acmeContact})
		err = c.a.Register()
		if err != nil {
			return c, err
		}
	} else if err == nil {
		logger.Debugf("Private key found, initializing")
		c.a = acme.NewAcme(acme.Config{AccountKey: accountKey, Contact: acmeContact})
	} else {
		return c, err
	}
	return c, nil
}

func (c *Cert) verifyDomains(params CreateCertParams) ([]WorkQueueItem, error) {
	var (
		err             error
		verifiedDomains []string
		domainsToVerify []string
		workQueueItems  []WorkQueueItem
		name            string
		domains         []string
	)
	name = params.Name
	domains = params.Domains

	logger.Debugf("Creating cert(s) for: %s", strings.Join(domains, ","))
	for _, domain := range domains {
		alreadyVerified := false
		challenge := ChallengeParams{Domain: domain, Name: name}
		challenge.AuthzURI, challenge.URI, challenge.Token, challenge.Body, alreadyVerified, err = c.a.AuthorizeUsingHttp(domain)
		if err != nil {
			return workQueueItems, err
		}
		if !alreadyVerified {
			logger.Debugf("%s not verified yet, starting verification", domain)
			challengeJSON, err := json.Marshal(challenge)
			if err != nil {
				return workQueueItems, err
			}
			err = c.s.WriteChallenge(name+"-"+domain, challengeJSON)
			if err != nil {
				return workQueueItems, err
			}
			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action:          "updateListenerWithChallenge",
				ChallengeParams: challenge,
			})
			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action:          "acceptChallenge",
				ChallengeParams: challenge,
			})
			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action:          "waitForValidation",
				ChallengeParams: challenge,
			})
			domainsToVerify = append(domainsToVerify, domain)
		} else {
			logger.Debugf("%s already verified", domain)
			verifiedDomains = append(verifiedDomains, domain)
		}
	}
	if len(domains) > 0 && len(domains) == len(verifiedDomains) {
		workQueueItems = append(workQueueItems, WorkQueueItem{
			Action: "createCert",
			CreateCertParams: CreateCertParams{
				Name:    name,
				Domains: domains,
			},
		})
	} else if len(domains) > 0 && len(domains) != len(verifiedDomains) {
		// still need to verify domains
		workQueueItems = append(workQueueItems, WorkQueueItem{
			Action: "createCertAfterVerification",
			CreateCertParams: CreateCertParams{
				Name:            name,
				Domains:         domains,
				DomainsToVerify: domainsToVerify,
			},
		})
	}

	return workQueueItems, nil
}
func (c *Cert) CreateCert(params CreateCertParams) (string, string, error) {
	var (
		err           error
		key           *rsa.PrivateKey
		domains       = params.Domains
		name          = params.Name
		certBundle    []byte
		privateKeyPem string
	)

	key, err = c.s.GetPrivateKey(name)
	if err != nil && err == c.s.GetError("errNotExist") {
		err = c.s.CreateKey(name)
		if err != nil {
			return "", "", err
		}
		key, err = c.s.GetPrivateKey(name)
	}
	if err != nil && err != c.s.GetError("errNotExist") {
		return "", "", err
	}
	csr, err := c.a.CreateCSR(domains, key)
	if err != nil {
		return "", "", err
	}
	der, _, err := c.a.CreateCert(csr)
	if err != nil {
		return "", "", err
	}
	leaf, bundle, err := c.a.GetLeafAndValidateCert(domains[0], der, key)
	if err != nil {
		return "", "", err
	}

	for _, certInBundle := range bundle {
		certBundle = append(certBundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certInBundle.Raw})...)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	err = c.s.WriteCert(name, cert)
	if err != nil {
		return "", "", err
	}

	err = c.s.WriteCertBundle(name, certBundle)
	if err != nil {
		return string(certBundle), privateKeyPem, err
	}

	privateKeyPem, err = c.s.GetPrivateKeyPem(name)
	if err != nil {
		return "", "", err
	}

	return string(certBundle), privateKeyPem, nil
}

func (c *Cert) acceptChallenge(params ChallengeParams) error {
	return c.a.AuthorizeUsingHttpAccept(params.Domain)
}
