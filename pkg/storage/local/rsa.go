package local

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	if err != nil {
		return err
	}
	if err := os.Chmod(fileName, 0600); err != nil {
		return err
	}
	return nil
}
func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) error {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		return err
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	if err != nil {
		return err
	}
	return nil
}
func getPublicKey(input []byte) (*rsa.PublicKey, error) {
	var (
		err        error
		pemDecoded *pem.Block
		key        interface{}
		publicKey  *rsa.PublicKey
		ok         bool
	)

	pemDecoded, _ = pem.Decode(input)
	if pemDecoded == nil {
		return nil, errors.New("Public pem in wrong format")
	}

	if key, err = x509.ParsePKIXPublicKey(pemDecoded.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(pemDecoded.Bytes); err == nil {
			key = cert.PublicKey
		} else {
			return nil, err
		}
	}

	if publicKey, ok = key.(*rsa.PublicKey); !ok {
		return nil, errors.New("Public pem is not public rsa key")
	}

	return publicKey, nil
}
func getPrivateKey(input []byte) (*rsa.PrivateKey, error) {
	var (
		err        error
		pemDecoded *pem.Block
		key        interface{}
		privateKey *rsa.PrivateKey
		ok         bool
	)

	pemDecoded, _ = pem.Decode(input)
	if pemDecoded == nil {
		return nil, errors.New("Private pem in wrong format")
	}

	key, err = x509.ParsePKCS1PrivateKey(pemDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	if privateKey, ok = key.(*rsa.PrivateKey); !ok {
		return nil, errors.New("Private pem is not private rsa key")
	}

	return privateKey, nil
}
