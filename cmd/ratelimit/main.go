package main

import (
	"context"
	"fmt"
	"log"
	"net"

	ratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"google.golang.org/grpc"
)

func main() {

	rateLimitService := &RateLimitService{}

	grpcServer := grpc.NewServer()
	ratelimit.RegisterRateLimitServiceServer(grpcServer, rateLimitService)
	l, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("Listening on tcp://:9001")
	grpcServer.Serve(l)
}

type RateLimitService struct{}

func (s *RateLimitService) ShouldRateLimit(ctx context.Context, req *ratelimit.RateLimitRequest) (*ratelimit.RateLimitResponse, error) {
	fmt.Printf("Req: %+v\n", req)
	return nil, nil
}
