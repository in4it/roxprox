package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"

	"github.com/coocood/freecache"
	ratelimitExt "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	ratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"google.golang.org/grpc"
)

const cache_mb_size = 512
const expiry = 60
const limit = 5

var (
	DebugLogger   *log.Logger
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
)

func main() {
	// init loggers
	DebugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	grpcServer := grpc.NewServer()
	ratelimit.RegisterRateLimitServiceServer(grpcServer, newRateLimitService())
	l, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("Listening on tcp://:8081")
	grpcServer.Serve(l)
}

func newRateLimitService() *RateLimitService {
	r := &RateLimitService{}
	// initialize cache
	cacheSize := cache_mb_size * 1024 * 1024
	r.cache = freecache.NewCache(cacheSize)
	debug.SetGCPercent(20)
	r.startvalue = make([]byte, 8)
	binary.LittleEndian.PutUint64(r.startvalue, 1)
	return r
}

//RateLimitService is a Rate Limit Service implementing ShouldRateLimit
type RateLimitService struct {
	cache      *freecache.Cache
	startvalue []byte
}

func debugLogger(str string) {
	if os.Getenv("DEBUG") != "" {
		DebugLogger.Println(str)
	}
}

//ShouldRateLimit is triggered for every request. This function determines whether to rate limit the request or not
func (r *RateLimitService) ShouldRateLimit(ctx context.Context, req *ratelimit.RateLimitRequest) (*ratelimit.RateLimitResponse, error) {
	debugLogger(fmt.Sprintf("Req: %+v", req))
	key := []byte(req.Domain + ":" + getDescriptorsToString(req.Descriptors))

	curValue, err := r.cache.GetOrSet(key, r.startvalue, expiry)
	if err != nil {
		return handleError(err)
	}
	if curValue == nil {
		// new value, returning OK
		debugLogger(fmt.Sprintf("Key: %s (length: %d), Value: %d", string(key), len(key), binary.LittleEndian.Uint64(r.startvalue)))
		return &ratelimit.RateLimitResponse{
			OverallCode: ratelimit.RateLimitResponse_OK,
		}, nil

	}

	curValueInt64 := binary.LittleEndian.Uint64(curValue)

	if curValueInt64+1 >= limit {
		InfoLogger.Printf("Rate limited: %s\n", string(key))
		return &ratelimit.RateLimitResponse{
			OverallCode: ratelimit.RateLimitResponse_OVER_LIMIT,
		}, nil
	}

	newValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(newValue, curValueInt64+1)
	err = r.cache.Set(key, newValue, expiry)
	if err != nil {
		return handleError(err)
	}

	debugLogger(fmt.Sprintf("Key: %s (length: %d), Value: %d", string(key), len(key), curValueInt64+1))

	return &ratelimit.RateLimitResponse{
		OverallCode: ratelimit.RateLimitResponse_OK,
	}, nil
}
func handleError(err error) (*ratelimit.RateLimitResponse, error) {
	ErrorLogger.Printf("%s", err)
	return &ratelimit.RateLimitResponse{
		OverallCode: ratelimit.RateLimitResponse_OK,
	}, err
}

func getDescriptorsToString(descriptors []*ratelimitExt.RateLimitDescriptor) string {
	var res string
	for _, descriptor := range descriptors {
		for _, v := range descriptor.Entries {
			res += v.Key + ":" + v.Value + ","
		}
	}
	return strings.TrimSuffix(res, ",")
}
