#
# Build go project
#
FROM golang:1.24.7-alpine AS go-builder

WORKDIR /roxprox

COPY . .

RUN apk add -u -t build-tools curl git && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o envoy-control-plane cmd/envoy-control-plane/main.go && \
    apk del build-tools && \
    rm -rf /var/cache/apk/*

#
# Runtime container
#
FROM alpine:3.22.2

WORKDIR /app

RUN apk --no-cache add ca-certificates bash curl shadow

COPY --from=go-builder /roxprox/envoy-control-plane .

# create a non-root user to run the application
RUN useradd -u 1000 -U -m appuser \
    && chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

ENTRYPOINT ["./envoy-control-plane"]
