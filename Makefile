GOARCH = amd64
SERVER_BINARY = envoy-control-plane

build-darwin:
	GOOS=darwin GOARCH=${GOARCH} go build ${LDFLAGS} -o ${SERVER_BINARY}-darwin-${GOARCH} cmd/envoy-control-plane/main.go 

build-linux:
	GOOS=linux GOARCH=${GOARCH} go build ${LDFLAGS} -o ${SERVER_BINARY}-linux-${GOARCH} cmd/envoy-control-plane/main.go 

test:
	go test ./...
