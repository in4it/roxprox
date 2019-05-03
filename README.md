# envoy-autocert

Envoy autocert is an envoy control plane that lets you issue (and renew) certs automatically through Let's encrypt or any other ACME-compatible provider. It controls one or more envoy proxies that sit in front of your app or service mesh.

You can download the server binary from the releases, or use the docker image.

## Current status
The first version works, but the project is still WIP.

## Run envoy-autocert
You can find configuration examples in resources/example-config
```
./envoy-control-plane-darwin-amd64 -storage-path data/ -acme-contact <your-email-address>
```

## Run envoy
There is an example envoy.yaml in the resources/ directory. Make sure to change the "address: 127.0.0.1" to the ip/host of the control-plane. You can start envoy with
```
docker run --rm -it --network="host" -v "${PWD}/resources/envoy.yaml":/etc/envoy/envoy.yaml envoyproxy/envoy:v1.10.0
```
## Configuration

You can configure endpoints using yaml definitions. Here's an example yaml definition that you can put in your data/ folder:

```
api: proxy.in4it.io/v1
kind: rule
metadata:
  name: mocky
spec:
  certificate: "letsencrypt"
  conditions:
    - hostname: mocky-1.in4it.io
    - hostname: mocky-2.in4it.io
  actions:
    - proxy:
        hostname: www.mocky.io
        port: 443
```

This will run the ACME validation on both hostnames (mocky-1.in4it.io and mocky-2.in4it.io). If successful, it'll create an https listener that redirects to www.mocky.io, a mocking service.