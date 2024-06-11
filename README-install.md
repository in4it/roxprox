# Install

## Instructions for ECS deploy without terraform (see terraform instructions below)
* git clone this repository or download the files from [resources/ecs/](resources/ecs/)
* Create an S3 bucket. You can copy [resources/mocky.yaml](resources/mocky.yaml) into config/mocky.yaml to proxy an example website
* Run the following commands to create an ECS cluster with roxprox (control plane) and envoy (data plane):

```
# IAM Execution Roles
aws iam create-role --role-name roxprox-execution-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name roxprox-execution-role --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
AWS_REGION=us-east-1 AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text) envsubst < roxprox-executionrole.template.json > roxprox-executionrole.json
aws iam put-role-policy --role-name roxprox-execution-role --policy-name roxprox-policy --policy-document file://roxprox-executionrole.json
# IAM Task Roles
aws iam create-role --role-name roxprox-task-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
S3_BUCKET=your-s3-bucket AWS_REGION=us-east-1 AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text) envsubst < roxprox-taskrole.template.json > roxprox-taskrole.json # change S3_BUCKET to your s3 bucket
aws iam put-role-policy --role-name roxprox-task-role --policy-name roxprox-policy --policy-document file://roxprox-taskrole.json
# ECS Cluster
aws ecs create-cluster --cluster-name roxprox-example
# Create SQS notification queue
aws sqs create-queue --queue-name "your-s3-bucket-notifications"
```

* Register the ECS service. Make sure to change the S3 and AWS_REGION variables:
```
aws ssm put-parameter --name envoy-config --type String --value $(cat envoy-config.yaml |base64)
S3_BUCKET=your-s3-bucket AWS_REGION=us-east-1 AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text) envsubst < roxprox.template.json > roxprox.json
aws logs create-log-group --log-group-name roxprox
```
* Deploy the ECS service. Make sure to specify a subnet and security group (http proxy port is tcp port 10000):

```
aws ecs register-task-definition --cli-input-json file://roxprox.json
aws ecs create-service --cluster roxprox-example --service-name roxprox --task-definition roxprox --desired-count 1 --network-configuration 'awsvpcConfiguration={subnets=[subnet-123],securityGroups=sg-123,assignPublicIp=ENABLED}' --launch-type FARGATE
```

* You can verify the task is launched in the ECS Console
* The http proxy is available on port 10000. Make sure to open this port in the security group before testing.
* If you're using the mocky.yaml test, try to curl the service on port 10000 with -H "Host: test.example.com"
* You can either put a ALB/NLB in front, or integrate it within your internal VPC network 

## Cleanup
```
aws ecs update-service --cluster roxprox-example --service roxprox --desired-count 0
aws ecs delete-service --cluster roxprox-example --service roxprox
aws ecs deregister-task-definition --task-definition roxprox:1
aws ecs delete-cluster --cluster roxprox-example
aws iam delete-role-policy --role-name roxprox-execution-role --policy-name roxprox-policy
aws iam detach-role-policy --role-name roxprox-execution-role --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
aws iam delete-role --role-name roxprox-execution-role
aws iam delete-role-policy --role-name roxprox-task-role --policy-name roxprox-policy
aws iam delete-role --role-name roxprox-task-role
aws logs delete-log-group --log-group-name roxprox
aws sqs delete-queue --queue-url "your-s3-bucket-notifications"
```

## Roxprox install (using Terraform)

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

To test the installation, hit the newly created loadbalancer endpoint with curl or a browser. If you used the example, you can use curl:
```
curl http://example.com -v -H "Host: test.example.com"
```

## Notes

* No sensitive information is stored.
* The configuration in your S3 bucket
* The envoy config file is in the parameter store
* TLS on the loadbalancer is enabled, encryption at rest of the configuration and s3 bucket can be configured
* No cryptographic keys need to be rotated, you can use KMS as the key store
* To verify container health, go to the ECS console and check whether the roxprox and envoy tasks are running. Use the logs in Cloudwatch Logs to see if no errors are present