#
# Build go project
#
FROM golang:1.24-alpine AS go-builder

WORKDIR /roxprox

COPY . .

RUN apk add -u -t build-tools curl git && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o envoy-control-plane cmd/envoy-control-plane/main.go && \
    apk del build-tools && \
    rm -rf /var/cache/apk/*

#
# Runtime container
#
FROM alpine:3.21.3

WORKDIR /app

RUN apk --no-cache add ca-certificates bash curl

COPY --from=go-builder /roxprox/envoy-control-plane .

ENTRYPOINT ["./envoy-control-plane"]
