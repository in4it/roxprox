package main

import (
	"flag"
	"os"
	"strings"

	envoy "github.com/in4it/roxprox/pkg/envoy"
	"github.com/in4it/roxprox/pkg/management"
	storage "github.com/in4it/roxprox/pkg/storage"
	"github.com/juju/loggo"
)

var logger = loggo.GetLogger("envoy-control-plane")

func main() {
	var (
		err                  error
		loglevel             string
		storageType          string
		storagePath          string
		storageBucket        string
		storageNotifications string
		awsRegion            string
		acmeContact          string
		s                    storage.Storage
	)
	flag.StringVar(&loglevel, "loglevel", "INFO", "log level")
	flag.StringVar(&storageType, "storage-type", "local", "storage type")
	flag.StringVar(&storagePath, "storage-path", "", "storage path")
	flag.StringVar(&storageBucket, "storage-bucket", "", "s3 storage bucket")
	flag.StringVar(&storageNotifications, "storage-notifications", "", "s3 storage notifications")
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
		s, err = storage.NewLocalStorage(storagePath)
		if err != nil {
			logger.Errorf("Couldn't inialize storage: %s", err)
			os.Exit(1)
		}
	} else if storageType == "s3" {
		startNotificationQueue := true
		s, err = storage.NewS3Storage(storageBucket, storagePath, awsRegion, storageNotifications, startNotificationQueue)
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

	if acmeContact != "" {
		err = xds.StartRenewalQueue()
		if err != nil {
			logger.Errorf("Couldn't start renewal queue: %s", err)
		}
	} else {
		logger.Infof("Not starting renewal queue: acme contact is empty")
	}

	// run forever
	select {}

}
