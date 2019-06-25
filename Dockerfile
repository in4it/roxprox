#
# Build go project
#
FROM golang:1.12-alpine as go-builder

WORKDIR /roxprox

COPY . .

RUN apk add -u -t build-tools curl git && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o envoy-control-plane cmd/envoy-control-plane/main.go && \
    apk del build-tools && \
    rm -rf /var/cache/apk/*

#
# Runtime container
#
FROM alpine:latest  

WORKDIR /app

RUN apk --no-cache add ca-certificates bash curl

COPY --from=go-builder /roxprox/envoy-control-plane .

ENTRYPOINT ["./envoy-control-plane"]