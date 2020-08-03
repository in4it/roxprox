package main

import (
	"fmt"
	"log"
	"net"
	"time"

	alf "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	accessloggrpc "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
)

func main() {

	alsv3 := &AccessLogService{}

	grpcServer := grpc.NewServer()
	v3.RegisterAccessLogServiceServer(grpcServer, alsv3)
	l, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("Listening on tcp://localhost:9001")
	grpcServer.Serve(l)
}

type AccessLogService struct{}

func (s *AccessLogService) StreamAccessLogs(stream accessloggrpc.AccessLogService_StreamAccessLogsServer) error {
	log.Println("Started stream")
	var logName string
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if msg.Identifier != nil {
			logName = msg.Identifier.LogName
			log.Println("Log name:", logName)
		}
		switch entries := msg.LogEntries.(type) {
		case *accessloggrpc.StreamAccessLogsMessage_HttpLogs:
			for _, entry := range entries.HttpLogs.LogEntry {
				if entry != nil {
					common := entry.CommonProperties
					req := entry.Request
					resp := entry.Response
					if common == nil {
						common = &alf.AccessLogCommon{}
					}
					if req == nil {
						req = &alf.HTTPRequestProperties{}
					}
					if resp == nil {
						resp = &alf.HTTPResponseProperties{}
					}
					log.Println(fmt.Sprintf("[%s-%s] %s %s %s %d %s %s",
						logName, time.Now().Format(time.RFC3339), req.Authority, req.Path, req.Scheme,
						resp.ResponseCode.GetValue(), req.RequestId, common.UpstreamCluster))
				}
			}
		case *accessloggrpc.StreamAccessLogsMessage_TcpLogs:
			for _, entry := range entries.TcpLogs.LogEntry {
				if entry != nil {
					common := entry.CommonProperties
					if common == nil {
						common = &alf.AccessLogCommon{}
					}
					log.Println(fmt.Sprintf("[%s-%s] tcp %s %s",
						logName, time.Now().Format(time.RFC3339), common.UpstreamLocalAddress, common.UpstreamCluster))
				}
			}
		default:
			log.Println("empty log message")
		}
	}
}
