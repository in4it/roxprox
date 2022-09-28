package s3

import (
	"context"

	n "github.com/in4it/roxprox/proto/notification/github.com/in4it/roxprox/proto/notification"
)

const (
	port = ":50051"
)

// server is used to implement notification.
type NotificationReceiver struct {
	queue chan []*n.NotificationRequest_NotificationItem
}

func (s *NotificationReceiver) SendNotification(ctx context.Context, in *n.NotificationRequest) (*n.NotificationReply, error) {
	notificationLogger.Debugf("Received %d events", len(in.GetNotificationItem()))
	s.queue <- in.GetNotificationItem()
	return &n.NotificationReply{Result: true}, nil
}

func (s *NotificationReceiver) GetQueue() chan []*n.NotificationRequest_NotificationItem {
	return s.queue
}

func NewNotificationReceiver() *NotificationReceiver {
	return &NotificationReceiver{queue: make(chan []*n.NotificationRequest_NotificationItem)}
}
