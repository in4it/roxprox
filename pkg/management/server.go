package management

import (
	"fmt"
	"net"

	n "github.com/in4it/roxprox/proto/notification"
	"github.com/juju/loggo"
	"google.golang.org/grpc"
)

const (
	port = ":50051"
)

var logger = loggo.GetLogger("management")

func NewServer(notificationServer n.NotificationServer) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	logger.Infof("Starting grpc management interface")
	s := grpc.NewServer()
	n.RegisterNotificationServer(s, notificationServer)

	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Errorf("failed to serve: %v", err)
		}
	}()

	return nil
}
