package s3

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/juju/loggo"
)

var notificationLogger = loggo.GetLogger("storage.notifications")

type NotificationEntry struct {
	messageID string
}

type Notifications struct {
	config    Config
	queueName string
	sqsSvc    *sqs.SQS
	queue     chan NotificationEntry
}

func newNotifications(config Config) *Notifications {
	return &Notifications{config: config, queueName: config.Bucket + "-notifications", queue: make(chan NotificationEntry)}
}

func (n *Notifications) StartQueue() error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(n.config.Region)},
	)
	if err != nil {
		return err
	}

	// Create a SQS service client.
	n.sqsSvc = sqs.New(sess)

	resultURL, err := n.sqsSvc.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: aws.String(n.queueName),
	})
	if err != nil {
		return err
	}

	go func() {
		for {
			result, err := n.sqsSvc.ReceiveMessage(&sqs.ReceiveMessageInput{
				QueueUrl: resultURL.QueueUrl,
				AttributeNames: aws.StringSlice([]string{
					"SentTimestamp",
				}),
				MaxNumberOfMessages: aws.Int64(10),
				MessageAttributeNames: aws.StringSlice([]string{
					"All",
				}),
				WaitTimeSeconds: aws.Int64(20),
			})
			if err != nil {
				notificationLogger.Errorf("ReceiveMessage error: %s", err)
			}

			fmt.Printf("Received %d messages.\n", len(result.Messages))
			if len(result.Messages) > 0 {
				fmt.Printf("%+v", result.Messages)
			}
		}
	}()

	return nil
}

func (n *Notifications) GetQueue() chan NotificationEntry {
	return n.queue
}
