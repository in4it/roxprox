# Install

## Terraform install

The best way to deploy roxprox+envoy to your infrastructure is by using our terraform module. You can download and install terraform from [https://developer.hashicorp.com/terraform/install](https://developer.hashicorp.com/terraform/install).

Once downloaded, create a new project directory, and create a proxy.tf file with the following contents:
```
module "roxprox" {
  source                          = "git@github.com:in4it/roxprox.git//terraform"
  envoy_release                   = "v1.29.3"
  release                         = "0.0.23"
  envoy_proxy_cpu                 = 512
  envoy_proxy_memory              = 1024
  loadbalancer                    = "alb"
  loadbalancer_alb_cert           = "example.com"
  control_plane_count             = 1
  envoy_proxy_count               = 1
  envoy_extra_target_group_arns   = [aws_lb_target_group.envoy-proxy-http-internal.id]
  lb_subnets                      = []    # aws public subnet to use (pick 2)
  subnets                         = []    # aws private subnet to use (typically corresponding private subnets in same AZ)
  s3_bucket                       = "roxprox-examplecom" # s3 bucket will be created. config resides in config/
  bucket_lb_logs                  = "roxprox-examplecom" # lb logs
}
```

Make sure to have a TLS certificate configured for the domain name specified as "loadbalancer_alb_cert". Fill out the lb_subnets and subnets (public and private vpc subnets to use). Modify the s3 bucket name. Ssee next step to upload configuration. Make changes where desired, then apply the configuration:

```
terraform init
terraform apply
```

This will launch the roxprox and envoy container within a new ECS cluster, the s3 bucket, and add a loadbalancer pointing to the envoy instance.

To change the configuration, upload a configuration yaml file to the s3 bucket (change the bucket with your bucket name):
```
aws s3 cp resources/example-proxy/mocky.yaml s3://roxprox-examplecom/config/mocky.yaml
```

To test the installation, hit the newly created loadbalancer endpoint with curl or a browser.