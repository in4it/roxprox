package s3

import (
	"context"
	"encoding/json"
	"net"
	"time"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	pbN "github.com/in4it/roxprox/proto/notification"
	"github.com/juju/loggo"
	"google.golang.org/grpc"
)

const (
	serviceDiscovery = "roxprox.roxprox.local"
	managementPort   = "50051"
)

var notificationLogger = loggo.GetLogger("storage.notifications")

type Notifications struct {
	config    Config
	queueName string
	sqsSvc    *sqs.SQS
	peers     map[Peer]pbN.NotificationClient
}

type Peer struct {
	address string
	port    string
}

func newNotifications(config Config) *Notifications {

	return &Notifications{
		config:    config,
		queueName: config.Bucket + "-notifications",
		peers:     make(map[Peer]pbN.NotificationClient),
	}
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

	logger.Infof("Starting SQS queue (%s)", aws.StringValue(resultURL.QueueUrl))
	go n.RunSQSQueue(aws.StringValue(resultURL.QueueUrl))

	return nil
}

func (n *Notifications) RunSQSQueue(queueURL string) {
	for {
		result, err := n.sqsSvc.ReceiveMessage(&sqs.ReceiveMessageInput{
			QueueUrl: aws.String(queueURL),
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

		if len(result.Messages) > 0 {
			var req pbN.NotificationRequest
			logger.Infof("Received %d messages from sqs.\n", len(result.Messages))
			for _, v := range result.Messages {
				var body S3NotificationBody
				err := json.Unmarshal([]byte(aws.StringValue(v.Body)), &body)
				if err != nil {
					notificationLogger.Errorf("Body unmarshal error: %s", err)
				}

				_, err = n.sqsSvc.DeleteMessage(&sqs.DeleteMessageInput{
					QueueUrl:      aws.String(queueURL),
					ReceiptHandle: v.ReceiptHandle,
				})
				if err != nil {
					notificationLogger.Errorf("DeleteMessage error: %s", err)
				}
				// relay message using body.s3.object.key
				// using second grpc interface (possible with service to service communication + service discovery)
				if len(body.Records) > 0 {
					req.NotificationItem = append(req.NotificationItem, &pbN.NotificationRequest_NotificationItem{
						Filename:  body.Records[0].S3.Object.Key,
						EventName: body.Records[0].EventName,
					})
				}
			}
			logger.Debugf("SendNotificationToPeers: %+v", req.NotificationItem)
			err = n.SendNotificationToPeers(req, n.lookupPeers(), 5)
			if err != nil {
				notificationLogger.Errorf("SendNotificationToPeers error: %s", err)
			}
		}
	}
}

func (n *Notifications) SendNotificationToPeers(req pbN.NotificationRequest, peerAddresses []Peer, timeout int) error {
	for _, v := range peerAddresses {
		if _, ok := n.peers[v]; !ok {
			// Set up a connection to the server.
			conn, err := grpc.Dial(v.address+":"+v.port, grpc.WithInsecure())
			if err != nil {
				return err
			}
			n.peers[v] = pbN.NewNotificationClient(conn)
			logger.Debugf("set up new grpc management connection with %s", v.address)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
		r, err := n.peers[v].SendNotification(ctx, &req)
		if err != nil {
			return fmt.Errorf("SendNotification error: %s", err)
		}
		if !r.GetResult() {
			return fmt.Errorf("SendNotification error: %s", err)
		}

		logger.Debugf("Sent notification to %s", v.address)
	}

	return nil
}

func (n *Notifications) lookupPeers() []Peer {
	peers := []Peer{}
	ips, err := net.LookupIP(serviceDiscovery)
	if err != nil {
		logger.Infof("LookupPeers: couldn't do DNS lookup on %s (using local only instead)", serviceDiscovery)
		peers = append(peers, Peer{
			address: "127.0.0.1",
			port:    managementPort,
		})
		return peers
	}
	for _, ip := range ips {
		peers = append(peers, Peer{
			address: ip.String(),
			port:    managementPort,
		})
	}
	return peers
}
