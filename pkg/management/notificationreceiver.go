package management

import (
	"context"

	envoy "github.com/in4it/roxprox/pkg/envoy"
	notification "github.com/in4it/roxprox/proto/notification/github.com/in4it/roxprox/proto/notification"
)

type NotificationReceiver struct {
	xds *envoy.XDS
	notification.UnimplementedNotificationServer
}

func (n *NotificationReceiver) SendNotification(ctx context.Context, in *notification.NotificationRequest) (*notification.NotificationReply, error) {
	logger.Debugf("Received %d events", len(in.GetNotificationItem()))
	err := n.xds.ReceiveNotification(in.GetNotificationItem())
	if err != nil {
		logger.Errorf("%s", err)
	}
	return &notification.NotificationReply{Result: true}, nil
}
func NewNotificationReceiver(xds *envoy.XDS) *NotificationReceiver {
	return &NotificationReceiver{
		xds: xds,
	}
}
