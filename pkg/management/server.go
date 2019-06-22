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
	queue chan []string
}

func (s *server) SendNotification(ctx context.Context, in *n.NotificationRequest) (*n.NotificationReply, error) {
	logger.Debugf("Received: %+v", in.Filename)
	s.queue <- in.Filename
	return &n.NotificationReply{Result: true}, nil
}

func (s *server) GetQueue() chan []string {
	return s.queue
}

func NewServer() (*server, error) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}
	logger.Infof("Starting grpc management interface")
	s := grpc.NewServer()
	serverObj := &server{queue: make(chan []string)}
	n.RegisterNotificationServer(s, serverObj)

	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Errorf("failed to serve: %v", err)
		}
	}()

	return serverObj, nil
}
