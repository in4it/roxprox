package awsmarketplace

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/marketplacemetering"
)

func Register(awsRegion string) error {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)})
	if err != nil {
		return fmt.Errorf("couldn't initialize S3: %s", err)
	}

	productCode := os.Getenv("PROD_CODE")

	// Create a MarketplaceMetering client from just a session.
	svc := marketplacemetering.New(sess)

	_, err = svc.RegisterUsage(&marketplacemetering.RegisterUsageInput{
		ProductCode:      aws.String(productCode),
		PublicKeyVersion: aws.Int64(1),
	})

	if err != nil {
		return fmt.Errorf("RegisterUsage error: %s", err)
	}

	return nil
}
