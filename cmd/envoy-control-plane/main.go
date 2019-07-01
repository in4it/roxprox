package main

import (
	"flag"
	"os"
	"strings"

	envoy "github.com/in4it/roxprox/pkg/envoy"
	"github.com/in4it/roxprox/pkg/management"
	storage "github.com/in4it/roxprox/pkg/storage"
	localStorage "github.com/in4it/roxprox/pkg/storage/local"
	"github.com/in4it/roxprox/pkg/storage/s3"
	"github.com/juju/loggo"
)

var logger = loggo.GetLogger("envoy-control-plane")

func main() {
	var (
		err           error
		loglevel      string
		storageType   string
		storagePath   string
		storageBucket string
		awsRegion     string
		acmeContact   string
		s             storage.Storage
	)
	flag.StringVar(&loglevel, "loglevel", "INFO", "log level")
	flag.StringVar(&storageType, "storage-type", "local", "storage type")
	flag.StringVar(&storagePath, "storage-path", "", "storage path")
	flag.StringVar(&storageBucket, "storage-bucket", "", "s3 storage bucket")
	flag.StringVar(&awsRegion, "aws-region", "", "AWS region")
	flag.StringVar(&acmeContact, "acme-contact", "", "acme contact for TLS certs")

	flag.Parse()

	loglevel = strings.ToUpper(loglevel)

	if loglevel == "DEBUG" || loglevel == "INFO" || loglevel == "TRACE" || loglevel == "ERROR" {
		loggo.ConfigureLoggers(`<root>=` + loglevel)
	} else {
		loggo.ConfigureLoggers(`<root>=INFO`)
	}

	if storageType == "local" {
		s, err = storage.NewStorage(storageType, localStorage.Config{Path: storagePath})
		if err != nil {
			logger.Errorf("Couldn't inialize storage: %s", err)
			os.Exit(1)
		}
	} else if storageType == "s3" {
		if storageBucket == "" {
			logger.Errorf("No bucket specified")
			os.Exit(1)
		}
		if strings.HasSuffix(storagePath, "/") {
			storagePath = storagePath[:len(storagePath)-1]
		}
		s, err = storage.NewStorage(storageType, s3.Config{Prefix: storagePath, Bucket: storageBucket, Region: awsRegion})
		if err != nil {
			logger.Errorf("Couldn't inialize storage: %s", err)
			os.Exit(1)
		}
	} else {
		panic("unknown storage")
	}

	// start management server
	notificationQueue, err := management.NewServer()
	if err != nil {
		logger.Errorf("Couldn't start management interface: %s", err)
		os.Exit(1)
	}

	xds := envoy.NewXDS(s, acmeContact, "8080")

	logger.Infof("Importing Rules")

	err = xds.ImportObjects()
	if err != nil {
		logger.Errorf("Couldn't import rules: %s", err)
	}

	xds.StartObservingNotifications(notificationQueue.GetQueue())

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
