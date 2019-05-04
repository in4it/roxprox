#
# Build go project
#
FROM golang:1.12-alpine as go-builder

WORKDIR /go/src/github.com/in4it/envoy-autocert

COPY . .

RUN apk add -u -t build-tools curl git && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
    dep ensure && \
    apk del build-tools && \
    rm -rf /var/cache/apk/*

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o envoy-control-plane cmd/envoy-control-plane/main.go

#
# Runtime container
#
FROM alpine:latest  

WORKDIR /app

RUN apk --no-cache add ca-certificates bash curl

COPY --from=go-builder /go/src/github.com/in4it/envoy-autocert/envoy-control-plane .

ENTRYPOINT ["./envoy-control-plane"]