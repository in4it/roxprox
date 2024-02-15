module github.com/in4it/roxprox

go 1.21

replace github.com/golang/mock v1.4.3 => github.com/golang/mock v1.4.4

require (
	github.com/aws/aws-sdk-go v1.38.69
	github.com/envoyproxy/go-control-plane v0.11.1
	github.com/google/go-cmp v0.5.9
	github.com/google/uuid v1.3.0
	github.com/juju/loggo v0.0.0-20200526014432-9ce3a2e09b5e
	golang.org/x/crypto v0.17.0
	google.golang.org/grpc v1.55.0
	google.golang.org/protobuf v1.30.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/census-instrumentation/opencensus-proto v0.4.1 // indirect
	github.com/cncf/xds/go v0.0.0-20230428030218-4003588d1b74 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.0.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20230526203410-71b5a4ffd15e // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230526203410-71b5a4ffd15e // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230526203410-71b5a4ffd15e // indirect
)
