package management

import (
	"context"
	"fmt"
	"log"
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
type server struct{}

func (s *server) SendNotification(ctx context.Context, in *n.NotificationRequest) (*n.NotificationReply, error) {
	log.Printf("Received: %+v", in.Filename)
	return &n.NotificationReply{Result: true}, nil
}

func NewServer() error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	logger.Infof("Starting grpc management interface")
	s := grpc.NewServer()
	n.RegisterNotificationServer(s, &server{})

	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Errorf("failed to serve: %v", err)
		}
	}()

	return nil
}
