# envoy-autocert

Envoy autocert is an envoy control plane that lets you issue (and renew) certs automatically through Let's encrypt or any other ACME-compatible provider. It controls one or more envoy proxies that sit in front of your app or service mesh.

You can download the server binary from the releases, or use the docker image.

## Current status
The first version works, but the project is still WIP.

## Run envoy-autocert
You can find configuration examples in resources/example-config
```
./envoy-control-plane-linux-amd64 -storage-path data/ -acme-contact <your-email-address>
```

You can use local storage (default) or s3 storage. To use s3 storage, use:

```
./envoy-control-plane-linux-amd64 -acme-contact <your-email-address> -storage-type s3 -storage-bucket your-bucket-name -aws-region your-aws-region
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

## Run on AWS with terraform

There is a terraform module available in this repository. It'll configure an S3 bucket, a Network Loadbalancer, and 3 fargate containers. The container setup consist of 2 envoy proxies (one for http and one for https), and the envoy-autocert server. To start using it, add the following code to your terraform project:

```
module "envoy-autocert" {
  source              = "github.com/in4it/envoy-autocert//terraform"
  release             = "latest"                                     # use a tag or use latest for master
  acme_contact        = "your-email"                                 # email contact used by Let's encrypt
  control_plane_count = 1                                            # desired controle plane instances
  envoy_proxy_count   = 1                                            # envoy proxy count (there will be still one for http and one for https, due to the AWS Fargate/NLB limitations)
  subnets             = ["subnet-1234abcd"]                          # AWS subnet to use
  s3_bucket           = "envoy-autocert"                             # s3 bucket to use
}
```

You'll still need to upload the configuration to the s3 bucket


# build 

```
protoc -I proto/ proto/notification.proto --go_out=plugins=grpc:proto/notification
make build-linux  # linux
make build-darwin # darwin
```
