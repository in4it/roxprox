#
# envoy (http)
#

locals {
  envoy_config_vars = {
    CLUSTER           = "roxprox"
    ID                = "roxprox-http"
    ADDRESS           = "roxprox.roxprox.local"
    DATADOG           = "datadog.roxprox.local"
    ADMIN_PORT        = "9909"
    ALS_CLUSTER_NAME  = var.envoy_als_cluster_name
    ALS_ADDRESS       = var.envoy_als_address
    ALS_PORT          = var.envoy_als_port
    RATELIMIT_ADDRESS = var.ratelimit_address
    ENABLE_ALS        = var.enable_als
    ENABLE_DATADOG    = var.enable_datadog
    ENABLE_RATELIMIT  = var.enable_ratelimit
  }
}

resource "aws_ssm_parameter" "envoy-config-http" {
  name  = "/roxprox/envoy.yaml"
  type  = "String"
  value = base64encode(jsonencode(jsondecode(templatefile("${path.module}/templates/envoy-config.tmpl", local.envoy_config_vars))))
}

resource "aws_ecs_task_definition" "envoy-proxy" {
  count                    = var.enable_appmesh ? 0 : 1
  family                   = "envoy-proxy"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-envoy-proxy-task-role.arn
  cpu                      = var.envoy_proxy_cpu
  memory                   = var.envoy_proxy_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = templatefile("${path.module}/templates/envoy.json.tpl", {
    mtls                  = var.mtls
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release
    ENVOY_CONFIG          = aws_ssm_parameter.envoy-config-http.arn
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    EXTRA_CONTAINERS      = var.extra_containers == "" ? "" : ",${var.extra_containers}"
    EXTRA_DEPENDENCY      = var.extra_dependency == "" ? "" : var.enable_appmesh ? ",${var.extra_dependency}" : var.extra_dependency
    ULIMIT_NOFILE_SOFT    = var.envoy_nofile_soft_limit
    ULIMIT_NOFILE_HARD    = var.envoy_nofile_hard_limit
  })
}

resource "aws_ecs_task_definition" "envoy-proxy-appmesh" {
  count                    = var.enable_appmesh ? 1 : 0
  family                   = "envoy-proxy"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-envoy-proxy-task-role.arn
  cpu                      = var.envoy_proxy_appmesh_cpu
  memory                   = var.envoy_proxy_appmesh_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = templatefile("${path.module}/templates/envoy-appmesh.json.tpl", {
    mtls                  = var.mtls
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release
    ENVOY_CONFIG          = aws_ssm_parameter.envoy-config-http.arn
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    EXTRA_CONTAINERS      = var.extra_containers == "" ? "" : ",${var.extra_containers}"
    EXTRA_DEPENDENCY      = var.extra_dependency == "" ? "" : var.enable_appmesh ? ",${var.extra_dependency}" : var.extra_dependency
    ULIMIT_NOFILE_SOFT    = var.envoy_nofile_soft_limit
    ULIMIT_NOFILE_HARD    = var.envoy_nofile_hard_limit
  })

  proxy_configuration {
    type           = "APPMESH"
    container_name = "envoy"
    properties = {
      AppPorts         = "10000"
      EgressIgnoredIPs = "169.254.170.2,169.254.169.254"
      IgnoredUID       = "1337"
      ProxyEgressPort  = 15001
      ProxyIngressPort = 15000
    }
  }
}

resource "aws_ecs_service" "envoy-proxy" {
  name            = "envoy-proxy"
  cluster         = aws_ecs_cluster.roxprox.id
  desired_count   = var.envoy_proxy_count
  task_definition = var.enable_appmesh ? aws_ecs_task_definition.envoy-proxy-appmesh[0].arn : aws_ecs_task_definition.envoy-proxy[0].arn

  launch_type = "FARGATE"

  network_configuration {
    subnets          = var.subnets
    security_groups  = var.loadbalancer == "alb" ? [aws_security_group.roxprox-envoy-alb[0].id] : [aws_security_group.roxprox-envoy-nlb[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.roxprox-envoy.arn
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.envoy-proxy-http.id
    container_name   = "envoy-proxy"
    container_port   = "10000"
  }

  dynamic "load_balancer" {
    for_each = var.envoy_extra_target_group_arns
      content {
        target_group_arn = load_balancer.value
        container_name   = "envoy-proxy"
        container_port   = "10000"
      }
  }

  dynamic "load_balancer" {
    for_each = var.mtls
      content {
        target_group_arn = aws_lb_target_group.envoy-proxy-mtls[load_balancer.key].id
        container_name   = "envoy-proxy"
        container_port   = load_balancer.value.port
      }
  }
}

#
# envoy (https)
#

resource "aws_ecs_task_definition" "envoy-proxy-https" {
  count                    = var.tls_listener ? 1 : 0
  family                   = "envoy-proxy-https"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-envoy-proxy-task-role.arn
  cpu                      = var.envoy_proxy_cpu
  memory                   = var.envoy_proxy_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = templatefile("${path.module}/templates/envoy.json.tpl", {
    mtls                  = var.mtls
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release
    ENVOY_CONFIG          = aws_ssm_parameter.envoy-config-http.arn
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    EXTRA_CONTAINERS      = var.extra_containers == "" ? "" : ",${var.extra_containers}"
    EXTRA_DEPENDENCY      = var.extra_dependency == "" ? "" : var.enable_appmesh ? ",${var.extra_dependency}" : var.extra_dependency
  })
}

resource "aws_ecs_task_definition" "envoy-proxy-https-appmesh" {
  count                    = var.tls_listener ? 1 : 0
  family                   = "envoy-proxy-https"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-envoy-proxy-task-role.arn
  cpu                      = var.envoy_proxy_appmesh_cpu
  memory                   = var.envoy_proxy_appmesh_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = templatefile("${path.module}/templates/envoy-appmesh.json.tpl", {
    mtls                  = var.mtls
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release
    ENVOY_CONFIG          = aws_ssm_parameter.envoy-config-http.arn
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    EXTRA_CONTAINERS      = var.extra_containers == "" ? "" : ",${var.extra_containers}"
    EXTRA_DEPENDENCY      = var.extra_dependency == "" ? "" : var.enable_appmesh ? ",${var.extra_dependency}" : var.extra_dependency
  })

  proxy_configuration {
    type           = "APPMESH"
    container_name = "envoy"
    properties = {
      AppPorts         = "10000"
      EgressIgnoredIPs = "169.254.170.2,169.254.169.254"
      IgnoredUID       = "1337"
      ProxyEgressPort  = 15001
      ProxyIngressPort = 15000
    }
  }
}

resource "aws_ecs_service" "envoy-proxy-https" {
  count           = var.tls_listener ? 1 : 0
  name            = "envoy-proxy-https"
  cluster         = aws_ecs_cluster.roxprox.id
  desired_count   = var.envoy_proxy_count
  task_definition = var.enable_appmesh ? aws_ecs_task_definition.envoy-proxy-https-appmesh[0].arn : aws_ecs_task_definition.envoy-proxy-https[0].arn
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnets
    security_groups  = var.loadbalancer == "alb" ? [aws_security_group.roxprox-envoy-alb[0].id] : [aws_security_group.roxprox-envoy-nlb[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.roxprox-envoy.arn
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.envoy-proxy-https[0].id
    container_name   = "envoy-proxy-https"
    container_port   = "10001"
  }

  dynamic "load_balancer" {
    for_each = var.mtls
      content {
        target_group_arn = aws_lb_target_group.envoy-proxy-mtls[load_balancer.key].id
        container_name   = "envoy-proxy"
        container_port   = load_balancer.value.port
      }
  }

}
