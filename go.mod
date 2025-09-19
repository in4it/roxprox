module github.com/in4it/roxprox

go 1.24.7

replace github.com/golang/mock v1.4.3 => github.com/golang/mock v1.4.4

require (
	github.com/aws/aws-sdk-go v1.55.8
	github.com/envoyproxy/go-control-plane v0.13.4
	github.com/envoyproxy/go-control-plane/envoy v1.32.4
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/juju/loggo v1.0.0
	golang.org/x/crypto v0.42.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.9
	gopkg.in/yaml.v2 v2.4.0
)

require (
	cel.dev/expr v0.24.0 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/envoyproxy/go-control-plane/ratelimit v0.1.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250908214217-97024824d090 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250908214217-97024824d090 // indirect
)
