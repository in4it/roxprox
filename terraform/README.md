<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_appmesh_virtual_node.envoy-proxy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appmesh_virtual_node) | resource |
| [aws_appmesh_virtual_node.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appmesh_virtual_node) | resource |
| [aws_appmesh_virtual_service.envoy-proxy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appmesh_virtual_service) | resource |
| [aws_appmesh_virtual_service.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appmesh_virtual_service) | resource |
| [aws_cloudwatch_log_group.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_ecs_cluster.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster) | resource |
| [aws_ecs_service.datadog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service) | resource |
| [aws_ecs_service.envoy-proxy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service) | resource |
| [aws_ecs_service.envoy-proxy-https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service) | resource |
| [aws_ecs_service.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service) | resource |
| [aws_ecs_service.roxprox-ratelimit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service) | resource |
| [aws_ecs_task_definition.datadog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.envoy-proxy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.envoy-proxy-appmesh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.envoy-proxy-https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.envoy-proxy-https-appmesh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.roxprox-appmesh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.roxprox-ratelimit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_ecs_task_definition.roxprox-ratelimit-appmesh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition) | resource |
| [aws_iam_role.datadog-ecs-task-execution-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.datadog-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.roxprox-ecs-task-execution-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.roxprox-envoy-proxy-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.roxprox-ratelimit-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.roxprox-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.datadog-ecs-extra-task-execution-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.datadog-ecs-task-execution-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.datadog-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-ecs-extra-task-execution-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-ecs-task-execution-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-envoy-extra-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-ratelimit-s3-sse-kms-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-ratelimit-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-s3-sse-kms-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.roxprox-task-role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_kms_alias.roxprox-s3-sse-kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.roxprox-s3-sse-kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_lb.lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb) | resource |
| [aws_lb.lb-mtls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb) | resource |
| [aws_lb_listener.lb-http](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_lb_listener.lb-https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_lb_listener.lb-mtls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_lb_listener_certificate.extra-certificates](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_certificate) | resource |
| [aws_lb_listener_rule.lb-https-redirect](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_rule) | resource |
| [aws_lb_target_group.envoy-proxy-http](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_lb_target_group.envoy-proxy-https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_lb_target_group.envoy-proxy-mtls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_s3_bucket.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_acl.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_notification.roxprox-notification](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_notification) | resource |
| [aws_s3_bucket_policy.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_security_group.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.roxprox-alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.roxprox-datadog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.roxprox-envoy-alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.roxprox-envoy-nlb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.roxprox-ratelimit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group_rule.roxprox-datadog-allow-apm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_service_discovery_private_dns_namespace.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/service_discovery_private_dns_namespace) | resource |
| [aws_service_discovery_service.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/service_discovery_service) | resource |
| [aws_service_discovery_service.roxprox-datadog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/service_discovery_service) | resource |
| [aws_service_discovery_service.roxprox-envoy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/service_discovery_service) | resource |
| [aws_service_discovery_service.roxprox-ratelimit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/service_discovery_service) | resource |
| [aws_sqs_queue.roxprox-notifications](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_ssm_parameter.envoy-config-http](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_acm_certificate.alb_cert](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/acm_certificate) | data source |
| [aws_acm_certificate.alb_cert_extra](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/acm_certificate) | data source |
| [aws_iam_policy_document.roxprox](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_subnet.subnet](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/subnet) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_acme_contact"></a> [acme\_contact](#input\_acme\_contact) | email address to be used for ACME - Let's encrypt will use this to notify you of expiring domains | `string` | `""` | no |
| <a name="input_appmesh_backends"></a> [appmesh\_backends](#input\_appmesh\_backends) | list of backends to be configured in the appmesh virtual node | `list` | `[]` | no |
| <a name="input_appmesh_envoy_release"></a> [appmesh\_envoy\_release](#input\_appmesh\_envoy\_release) | tag of appmesh envoy release | `string` | `"v1.11.1.1-prod"` | no |
| <a name="input_appmesh_name"></a> [appmesh\_name](#input\_appmesh\_name) | name of the app mesh | `string` | `""` | no |
| <a name="input_bucket_lb_logs"></a> [bucket\_lb\_logs](#input\_bucket\_lb\_logs) | name of s3 bucket to use for lb logs | `any` | n/a | yes |
| <a name="input_cloudwatch_log_retention_period"></a> [cloudwatch\_log\_retention\_period](#input\_cloudwatch\_log\_retention\_period) | cloudwatch retention period in days | `string` | `"0"` | no |
| <a name="input_cloudwatch_logs_kms"></a> [cloudwatch\_logs\_kms](#input\_cloudwatch\_logs\_kms) | kms key for CW logs encryption | `string` | `""` | no |
| <a name="input_control_plane_count"></a> [control\_plane\_count](#input\_control\_plane\_count) | number of control plane instances to run | `number` | `1` | no |
| <a name="input_datadog_api_key"></a> [datadog\_api\_key](#input\_datadog\_api\_key) | datadog api key | `string` | `""` | no |
| <a name="input_datadog_count"></a> [datadog\_count](#input\_datadog\_count) | datadog service count | `string` | `"2"` | no |
| <a name="input_datadog_env"></a> [datadog\_env](#input\_datadog\_env) | datadog APM default enviroment | `string` | `"none"` | no |
| <a name="input_datadog_extra_task_execution_policy"></a> [datadog\_extra\_task\_execution\_policy](#input\_datadog\_extra\_task\_execution\_policy) | datadog extra task execution policy | `string` | `""` | no |
| <a name="input_datadog_image"></a> [datadog\_image](#input\_datadog\_image) | datadog agent image | `string` | `"datadog/agent"` | no |
| <a name="input_datadog_image_version"></a> [datadog\_image\_version](#input\_datadog\_image\_version) | datadog agent image version | `string` | `"latest"` | no |
| <a name="input_datadog_log_level"></a> [datadog\_log\_level](#input\_datadog\_log\_level) | datadog log level | `string` | `"INFO"` | no |
| <a name="input_datadog_stats_url"></a> [datadog\_stats\_url](#input\_datadog\_stats\_url) | datadog stats url | `string` | `""` | no |
| <a name="input_dd_remote_configuration_enabled"></a> [dd\_remote\_configuration\_enabled](#input\_dd\_remote\_configuration\_enabled) | flag to enable/disable datadog remote configuration | `bool` | `true` | no |
| <a name="input_drop_invalid_header_fields"></a> [drop\_invalid\_header\_fields](#input\_drop\_invalid\_header\_fields) | true if needs to drop invalid header fields | `string` | `"false"` | no |
| <a name="input_enable_als"></a> [enable\_als](#input\_enable\_als) | flag to enable ALS integration | `bool` | `false` | no |
| <a name="input_enable_appmesh"></a> [enable\_appmesh](#input\_enable\_appmesh) | enable app mesh | `bool` | `false` | no |
| <a name="input_enable_datadog"></a> [enable\_datadog](#input\_enable\_datadog) | flag to enable datadog integration | `bool` | `false` | no |
| <a name="input_enable_lb_logs"></a> [enable\_lb\_logs](#input\_enable\_lb\_logs) | true to enable logs for LB | `string` | `"false"` | no |
| <a name="input_enable_ratelimit"></a> [enable\_ratelimit](#input\_enable\_ratelimit) | flag to enable ratelimit service | `bool` | `false` | no |
| <a name="input_envoy_als_address"></a> [envoy\_als\_address](#input\_envoy\_als\_address) | envoy access log server address | `string` | `"als"` | no |
| <a name="input_envoy_als_cluster_name"></a> [envoy\_als\_cluster\_name](#input\_envoy\_als\_cluster\_name) | envoy access log server cluster name | `string` | `"als_cluster"` | no |
| <a name="input_envoy_als_port"></a> [envoy\_als\_port](#input\_envoy\_als\_port) | envoiy access log server port | `number` | `9001` | no |
| <a name="input_envoy_autocert_loglevel"></a> [envoy\_autocert\_loglevel](#input\_envoy\_autocert\_loglevel) | log level | `string` | `"info"` | no |
| <a name="input_envoy_extra_target_group_arns"></a> [envoy\_extra\_target\_group\_arns](#input\_envoy\_extra\_target\_group\_arns) | extra target groups to add | `list` | `[]` | no |
| <a name="input_envoy_nofile_hard_limit"></a> [envoy\_nofile\_hard\_limit](#input\_envoy\_nofile\_hard\_limit) | envoy nofile hard limit | `number` | `4096` | no |
| <a name="input_envoy_nofile_soft_limit"></a> [envoy\_nofile\_soft\_limit](#input\_envoy\_nofile\_soft\_limit) | envoy nofile soft limit | `number` | `1024` | no |
| <a name="input_envoy_proxy_appmesh_cpu"></a> [envoy\_proxy\_appmesh\_cpu](#input\_envoy\_proxy\_appmesh\_cpu) | fargate task cpu when appmesh is enabled | `number` | `512` | no |
| <a name="input_envoy_proxy_appmesh_memory"></a> [envoy\_proxy\_appmesh\_memory](#input\_envoy\_proxy\_appmesh\_memory) | fargate task memory when appmesh is enabled | `number` | `1024` | no |
| <a name="input_envoy_proxy_count"></a> [envoy\_proxy\_count](#input\_envoy\_proxy\_count) | number of envoy proxies to run | `number` | `1` | no |
| <a name="input_envoy_proxy_cpu"></a> [envoy\_proxy\_cpu](#input\_envoy\_proxy\_cpu) | fargate task cpu | `number` | `256` | no |
| <a name="input_envoy_proxy_extra_sg"></a> [envoy\_proxy\_extra\_sg](#input\_envoy\_proxy\_extra\_sg) | additional security group allowing access to roxprox envoy | `string` | `""` | no |
| <a name="input_envoy_proxy_memory"></a> [envoy\_proxy\_memory](#input\_envoy\_proxy\_memory) | fargate task memory | `number` | `512` | no |
| <a name="input_envoy_release"></a> [envoy\_release](#input\_envoy\_release) | docker tag of envoy release | `string` | `"v1.15.0"` | no |
| <a name="input_extra_containers"></a> [extra\_containers](#input\_extra\_containers) | add extra containers to task definition | `string` | `""` | no |
| <a name="input_extra_dependency"></a> [extra\_dependency](#input\_extra\_dependency) | add extra dependencies to task definition | `string` | `""` | no |
| <a name="input_extra_task_execution_policy"></a> [extra\_task\_execution\_policy](#input\_extra\_task\_execution\_policy) | extra task execution policy for roxprox | `string` | `""` | no |
| <a name="input_extra_task_role_policy"></a> [extra\_task\_role\_policy](#input\_extra\_task\_role\_policy) | extra task role policy for roxprox | `string` | `""` | no |
| <a name="input_lb_subnets"></a> [lb\_subnets](#input\_lb\_subnets) | loadbalancer subnets to use | `list(string)` | n/a | yes |
| <a name="input_loadbalancer"></a> [loadbalancer](#input\_loadbalancer) | loadbalancer type to use | `string` | `"nlb"` | no |
| <a name="input_loadbalancer_alb_cert"></a> [loadbalancer\_alb\_cert](#input\_loadbalancer\_alb\_cert) | main loadbalancer alb certificate to use | `string` | `""` | no |
| <a name="input_loadbalancer_alb_cert_extra"></a> [loadbalancer\_alb\_cert\_extra](#input\_loadbalancer\_alb\_cert\_extra) | loadbalancer alb certificate to use (extra certificates) | `list` | `[]` | no |
| <a name="input_loadbalancer_healthcheck_matcher"></a> [loadbalancer\_healthcheck\_matcher](#input\_loadbalancer\_healthcheck\_matcher) | loadbalancer healthcheck matcher to use | `string` | `"200,404,301,302"` | no |
| <a name="input_loadbalancer_healthcheck_path"></a> [loadbalancer\_healthcheck\_path](#input\_loadbalancer\_healthcheck\_path) | loadbalancer healthcheck path to use | `string` | `"/"` | no |
| <a name="input_loadbalancer_https_forwarding"></a> [loadbalancer\_https\_forwarding](#input\_loadbalancer\_https\_forwarding) | if true, redirect all http traffic to https | `bool` | `false` | no |
| <a name="input_loadbalancer_ssl_policy"></a> [loadbalancer\_ssl\_policy](#input\_loadbalancer\_ssl\_policy) | ssl policy for the https listener to use | `string` | `"ELBSecurityPolicy-TLS13-1-2-2021-06"` | no |
| <a name="input_management_access_sg"></a> [management\_access\_sg](#input\_management\_access\_sg) | allow access to the management interface | `list` | `[]` | no |
| <a name="input_mtls"></a> [mtls](#input\_mtls) | list of mtls ports and ips allowed | `list` | `[]` | no |
| <a name="input_ratelimit_address"></a> [ratelimit\_address](#input\_ratelimit\_address) | n/a | `string` | `"roxprox-ratelimit.roxprox.local"` | no |
| <a name="input_ratelimit_count"></a> [ratelimit\_count](#input\_ratelimit\_count) | n/a | `number` | `1` | no |
| <a name="input_ratelimit_cpu"></a> [ratelimit\_cpu](#input\_ratelimit\_cpu) | n/a | `number` | `1024` | no |
| <a name="input_ratelimit_debug"></a> [ratelimit\_debug](#input\_ratelimit\_debug) | n/a | `bool` | `false` | no |
| <a name="input_ratelimit_memory"></a> [ratelimit\_memory](#input\_ratelimit\_memory) | n/a | `number` | `2048` | no |
| <a name="input_ratelimit_release"></a> [ratelimit\_release](#input\_ratelimit\_release) | n/a | `string` | `"latest"` | no |
| <a name="input_release"></a> [release](#input\_release) | roxprox release | `any` | n/a | yes |
| <a name="input_s3_bucket"></a> [s3\_bucket](#input\_s3\_bucket) | name of s3 bucket to use | `any` | n/a | yes |
| <a name="input_s3_bucket_sse"></a> [s3\_bucket\_sse](#input\_s3\_bucket\_sse) | Enable SSE for roxprox bucket | `bool` | `false` | no |
| <a name="input_sqs_kms_master_key_id"></a> [sqs\_kms\_master\_key\_id](#input\_sqs\_kms\_master\_key\_id) | KMS key arn to encrypt SQS queue | `string` | `""` | no |
| <a name="input_subnets"></a> [subnets](#input\_subnets) | subnets to use | `list(string)` | n/a | yes |
| <a name="input_tls_listener"></a> [tls\_listener](#input\_tls\_listener) | run a service for a tls (https) listener (true/false) | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_lb-arn"></a> [lb-arn](#output\_lb-arn) | n/a |
| <a name="output_lb-arn-suffix"></a> [lb-arn-suffix](#output\_lb-arn-suffix) | n/a |
| <a name="output_lb-dns-name"></a> [lb-dns-name](#output\_lb-dns-name) | n/a |
| <a name="output_lb-mtls-dns-name"></a> [lb-mtls-dns-name](#output\_lb-mtls-dns-name) | n/a |
| <a name="output_lb-mtls-zone-id"></a> [lb-mtls-zone-id](#output\_lb-mtls-zone-id) | n/a |
| <a name="output_lb-zone-id"></a> [lb-zone-id](#output\_lb-zone-id) | n/a |
| <a name="output_roxprox-alb-sg"></a> [roxprox-alb-sg](#output\_roxprox-alb-sg) | n/a |
| <a name="output_roxprox-envoy-sg"></a> [roxprox-envoy-sg](#output\_roxprox-envoy-sg) | n/a |
| <a name="output_roxprox-kms-arn"></a> [roxprox-kms-arn](#output\_roxprox-kms-arn) | n/a |
<!-- END_TF_DOCS -->