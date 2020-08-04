GOARCH = amd64
SERVER_BINARY = envoy-control-plane
RATELIMIT_BINARY = ratelimit

build-darwin: build-server-darwin build-ratelimit-darwin

build-server-darwin:
	GOOS=darwin GOARCH=${GOARCH} go build ${LDFLAGS} -o ${SERVER_BINARY}-darwin-${GOARCH} cmd/envoy-control-plane/main.go 

build-ratelimit-darwin:
	GOOS=darwin GOARCH=${GOARCH} go build ${LDFLAGS} -o ${RATELIMIT_BINARY}-darwin-${GOARCH} cmd/ratelimit/main.go 

build-server-linux:
	GOOS=linux GOARCH=${GOARCH} go build ${LDFLAGS} -o ${SERVER_BINARY}-linux-${GOARCH} cmd/envoy-control-plane/main.go 

build-ratelimit-linux:
	GOOS=linux GOARCH=${GOARCH} go build ${LDFLAGS} -o ${RATELIMIT_BINARY}-linux-${GOARCH} cmd/ratelimit/main.go 

test:
	go test ./...
