package management

import (
	"context"
	"fmt"
	"net"

	n "github.com/in4it/envoy-autocert/proto/notification"
	"github.com/juju/loggo"
	"google.golang.org/grpc"
)

const (
	port = ":50051"
)

var logger = loggo.GetLogger("management")

// server is used to implement notification.
type server struct {
	queue chan []*n.NotificationRequest_NotificationItem
}

func (s *server) SendNotification(ctx context.Context, in *n.NotificationRequest) (*n.NotificationReply, error) {
	logger.Debugf("Received %d events", len(in.GetNotificationItem()))
	s.queue <- in.GetNotificationItem()
	return &n.NotificationReply{Result: true}, nil
}

func (s *server) GetQueue() chan []*n.NotificationRequest_NotificationItem {
	return s.queue
}

func NewServer() (*server, error) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	logger.Infof("Starting grpc management interface")
	s := grpc.NewServer()
	serverObj := &server{queue: make(chan []*n.NotificationRequest_NotificationItem)}
	n.RegisterNotificationServer(s, serverObj)

	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Errorf("failed to serve: %v", err)
		}
	}()

	return serverObj, nil
}
