package main

import (
	"flag"

	envoy "github.com/in4it/envoy-autocert/pkg/envoy"
	storage "github.com/in4it/envoy-autocert/pkg/storage"
	localStorage "github.com/in4it/envoy-autocert/pkg/storage/local"
	"github.com/juju/loggo"
)

var logger = loggo.GetLogger("envoy-control-plane")

func main() {
	var (
		storageType string
		storagePath string
		acmeContact string
		s           storage.Storage
	)
	flag.StringVar(&storageType, "storage-type", "local", "storage type")
	flag.StringVar(&storagePath, "storage-path", "", "storage path")
	flag.StringVar(&acmeContact, "acme-contact", "", "acme contact for TLS certs")

	flag.Parse()

	loggo.ConfigureLoggers(`<root>=DEBUG`)

	if storageType == "local" {
		s = storage.NewStorage(storageType, localStorage.Config{Path: storagePath})
	} else {
		panic("unknown storage")
	}

	var err error

	xds := envoy.NewXDS(s, acmeContact)

	logger.Infof("Importing Rules")

	err = xds.ImportRules()
	if err != nil {
		logger.Errorf("Couldn't import rules: %s", err)
	}

	// Waiting for envoys to connect
	logger.Infof("Waiting for envoys to connect...")
	xds.WaitForFirstEnvoy()

	// start cert creation
	logger.Infof("Start certificate creation...")

	err = xds.CreateCertsForRules()
	if err != nil {
		logger.Errorf("Couldn't create certs: %s", err)
	}

	err = xds.StartRenewalQueue()
	if err != nil {
		logger.Errorf("Couldn't start renewal queue: %s", err)
	}

	// run forever
	select {}

}
