package awsmarketplace

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/marketplacemetering"
)

func reportUsage(sess *session.Session, productCode string) {
	svc := marketplacemetering.New(sess)

	for {
		_, err := svc.MeterUsage(&marketplacemetering.MeterUsageInput{
			ProductCode:    aws.String(productCode),
			Timestamp:      aws.Time(time.Now()),
			UsageDimension: aws.String("HourlyUsage"),
			UsageQuantity:  aws.Int64(1),
		})

		if err != nil {
			fmt.Printf("MeterUsage error: %s\n", err)
		}
		time.Sleep(1 * time.Hour)
	}
}
