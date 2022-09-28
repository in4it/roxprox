package s3

import (
	"fmt"
	"testing"

	pbN "github.com/in4it/roxprox/proto/notification/github.com/in4it/roxprox/proto/notification"
)

func TestLookupPeers(t *testing.T) {
	config := Config{
		Bucket: "bucket",
	}
	n := NewNotifications(config)
	peers := n.lookupPeers()
	fmt.Printf("%+v", peers)
	if len(peers) == 0 {
		t.Errorf("No peers returned")
	}
}
func TestSendNotificationToPeers(t *testing.T) {
	config := Config{
		Bucket: "bucket",
	}
	n := NewNotifications(config)
	peers := []Peer{
		{
			address: "192.168.199.123",
			port:    managementPort,
		},
		{
			address: "192.168.199.124",
			port:    managementPort,
		},
	}
	req := pbN.NotificationRequest{
		NotificationItem: []*pbN.NotificationRequest_NotificationItem{
			{
				Filename:  "test",
				EventName: "ObjectCreated:Put",
			},
		},
	}
	err := n.SendNotificationToPeers(req, peers, 1)
	if err == nil {
		t.Errorf("Expected error")
	}
}
