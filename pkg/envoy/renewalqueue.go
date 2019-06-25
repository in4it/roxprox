package envoy

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/in4it/roxprox/pkg/storage"
)

type RenewalQueue struct {
	c         chan struct{}
	s         storage.Storage
	cert      *Cert
	workQueue *WorkQueue
}

func NewRenewalQueue(s storage.Storage, acmeContact string, workQueue *WorkQueue) (*RenewalQueue, error) {
	c := make(chan struct{})
	cert, err := newCert(s, acmeContact)
	if err != nil {
		return nil, err
	}

	r := &RenewalQueue{c: c, s: s, cert: cert, workQueue: workQueue}

	return r, nil
}

func (r *RenewalQueue) StartQueue() {
	logger.Debugf("Starting Queue (runs once an hour)")
	ticker := time.NewTicker(60 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				logger.Debugf("Running checkRenewals")
				r.CheckRenewals()
			case <-r.c:
				ticker.Stop()
				return
			}
		}
	}()
}
func (r *RenewalQueue) CheckRenewals() error {
	var workQueueItems []WorkQueueItem
	certs, err := r.s.ListCerts()
	if err != nil {
		return err
	}

	for certName, certPEM := range certs {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return fmt.Errorf("failed to parse certificate PEM for %s", certName)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate for (%s): %s", certName, err.Error())
		}

		renewalDate := cert.NotAfter.AddDate(0, 0, -30)
		if time.Now().After(renewalDate) {
			logger.Debugf("Certificate %s needs to be renewed", certName)
			domains := []string{cert.Subject.CommonName}
			for _, v := range cert.DNSNames {
				if v != domains[0] {
					domains = append(domains, v)
				}
			}
			workQueueItems = append(workQueueItems, WorkQueueItem{
				Action: "verifyDomains",
				CreateCertParams: CreateCertParams{
					Name:    certName,
					Domains: domains,
				},
			})
		} else {
			timeleft := cert.NotAfter.Sub(time.Now()).Hours()
			timeleftToRenew := renewalDate.Sub(time.Now()).Hours()
			logger.Debugf("Certificate %s needs needs no renewal (expires in %.2f days, will renew in %.2f days)", certName, timeleft/24, timeleftToRenew/24)
		}
	}
	if len(workQueueItems) > 0 {
		r.workQueue.Submit(workQueueItems)
	}
	return nil
}
