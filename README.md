# roxprox

Envoy autocert is an envoy control plane with AWS Cloud support.

* Write & Store configuration in S3
* Instant s3 notifications update the envoy proxy without having to do a manual reload or restart
* ACME support to automatically verify, issue and setup letsencrypt certificates
* authn: support for JWT authentication
* authz: support for external grpc service which can authorize a connection
* Access Log Server support
* Compression support
* Ratelimit support
* Works stand-alone or serverless with AWS Fargate
* Traffic only passes the envoy proxy

## Run roxprox (local storage)

```
docker network create roxprox
docker run --rm -it --name envoy-control-plane --network roxprox -v $(PWD)/resources/example-proxy:/app/config in4it/roxprox -storage-type local -storage-path config -loglevel debug
```

## Run roxprox (s3 storage)

```
docker network create roxprox
docker run --rm -it --name envoy-control-plane --network roxprox in4it/roxprox -acme-contact <your-email-address> -storage-type s3 -storage-bucket your-bucket-name -aws-region your-aws-region
```

## Run envoy
There is an example envoy.yaml in the resources/ directory. Make sure to change the "address: $IP" to the ip/host of the control-plane. If you used the docker command above to create the network, you can use the following command to replace the IP:
```
cat resources/envoy.yaml |sed 's/$IP/'$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' envoy-control-plane |xargs)/ > resources/envoy-withip.yaml
```

Then run the envoy proxy:
```
docker run --rm -it -p 10000:10000 -p 10001:10001 -p 9901:9901 --network roxprox -v "$(PWD)/resources/envoy-withip.yaml":/etc/envoy/envoy.yaml envoyproxy/envoy:v1.15-latest
```

## Run access log serve
```
cd  resources/access-log-server
make docker
docker run --rm -it -p 9001:9001 --network roxprox --name als als
```

## Configuration
You can configure endpoints using yaml definitions. Below are example yaml definitions that you can put in your data/ folder.


### Simple reverse proxy (hostname + prefix)
```
api: proxy.in4it.io/v1
kind: rule
metadata:
  name: simple-reverse-proxy
spec:
  conditions:
    - hostname: test1.example.com
      prefix: /api
  actions:
    - proxy:
        hostname: target-example.com
        port: 443
```

### Simple reverse proxy (path)
```
api: proxy.in4it.io/v1
kind: rule
metadata:
  name: simple-reverse-proxy
spec:
  conditions:
    - path: /fixed-url
  actions:
    - proxy:
        hostname: target-example.com
        port: 443
```

### Simple reverse proxy (regex)
```
api: proxy.in4it.io/v1
kind: rule
metadata:
  name: simple-reverse-proxy
spec:
  conditions:
    - regex: "/api/v.*/health"
  actions:
    - proxy:
        hostname: target-example.com
        port: 443
```

### ALS
ALS enables the Access Log Server. You'll need to define a grpc cluster in envoy.yaml, because the access log server can only defined statically (a limitation in envoy). There is an example ALS server in [resources/access-log-server/](https://github.com/in4it/roxprox/tree/master/resources/access-log-server).

```
api: proxy.in4it.io/v1
kind: accessLogServer
metadata:
    name: accessLogServerExample
spec:
    address: "als"
    port: 9001
```

### Authn
```
api: proxy.in4it.io/v1
kind: rule
metadata:
  name: simple-reverse-proxy
spec:
  auth:
    jwtProvider: myJwtProvider
  conditions:
    - prefix: /
  actions:
    - proxy:
        hostname: target-example.com
        port: 443
---
api: proxy.in4it.io/v1
kind: jwtProvider
metadata:
  name: myJwtProvider
spec:
  remoteJwks: https://my-idp.com/.well-known/jwks.json
  issuer: myIssuer
  forward: true # forward jwt token to target
```

### Authorization example
```
api: proxy.in4it.io/v1
kind: authzFilter
metadata:
  name: example-authz
spec:
  hostname: localhost # hostname of service, can be localhost if deployed in same container / kubernetes pod / ecs task
  port: 8080
  timeout: 5s
  failureModeAllow: false  # if true, a failure of the service will still let clients reach the target servers
```

### Directresponse (for a Healthcheck)
```
api: proxy.in4it.io/v1
kind: rule
metadata:
  name: healthcheck
spec:
  conditions:
    - path: /.roxprox/health
  actions:
    - directResponse:
        status: 200
        body: "OK"
```

### Tracing
Tracing destination hostname (for example Datadog), can be defined in the envoy.yaml (because it's a static host).
```
api: proxy.in4it.io/v1
kind: tracing
metadata:
  name: tracing
spec:
  clientSampling: 100
  randomSampling: 100
  overallSampling: 100
```

### Compression
Compression can automatically compress the traffic between the backend clusters and the clients. The client only has to pass the "Content-Encoding" header.

```
api: proxy.in4it.io/v1
kind: compression
metadata:
  name: compression
spec:
  type: gzip
  disableOnEtagHeader: true
```

### Ratelimiting
Ratelimit allows you to ratelimit requests using descriptors (remote address, request headers, destination/source cluster). You define requestPerUnit and a unit type (second/minute/hour/day). Ratelimiting needs a grpc server configured by the name "ratelimit". See [github.com/in4it/roxprox-ratelimit](https://github.com/in4it/roxprox-ratelimit) for an in-memory ratelimit server.

```
api: proxy.in4it.io/v1
kind: rateLimit
metadata:
  name: ratelimit-example
spec:
  descriptors:
    - remoteAddress: true
  requestPerUnit: 1
  Unit: hour
---
api: proxy.in4it.io/v1
kind: rateLimit
metadata:
  name: ratelimit-example-authorized
spec:
  descriptors:
    - requestHeader: "Authorization"
    - destinationCluster: true
  requestPerUnit: 5
  Unit: minute
```

### TLS using letsencrypt
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

## Run on AWS with terraform

There is a terraform module available in this repository. It'll configure an S3 bucket, a Network Loadbalancer, and 3 fargate containers. The container setup consist of 2 envoy proxies (one for http and one for https), and the roxprox server. To start using it, add the following code to your terraform project:

```
module "roxprox" {
  source              = "github.com/in4it/roxprox//terraform"
  release             = "latest"                                     # use a tag or use latest for master
  acme_contact        = "your-email"                                 # email contact used by Let's encrypt, leave empty to disable TLS
  control_plane_count = 1                                            # desired controle plane instances
  envoy_proxy_count   = 1                                            # envoy proxy count (there will be still one for http and one for https, due to the AWS Fargate/NLB limitations)
  subnets             = ["subnet-1234abcd"]                          # AWS subnet to use
  s3_bucket           = "roxprox"                                    # s3 bucket to use
}
```

You'll still need to upload the configuration to the s3 bucket


# Manual build 

```
protoc -I proto/ proto/notification.proto --go_out=plugins=grpc:proto/notification
protoc -I proto/ proto/config.proto --go_out=plugins=grpc:proto/config
make build-linux  # linux
make build-darwin # darwin
```
