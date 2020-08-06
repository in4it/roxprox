locals {
  ratelimit_config_vars = {
    AWS_REGION            = data.aws_region.current.name
    RATELIMIT_RELEASE     = var.ratelimit_release
    S3_BUCKET             = var.s3_bucket
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    ENABLE_APPMESH        = var.enable_appmesh
    RATELIMIT_CACHE_SIZE  = max(var.ratelimit_memory - 512, var.ratelimit_memory / 2)
    RATELIMIT_DEBUG       = var.ratelimit_debug
  }
}

resource "aws_ecs_task_definition" "roxprox-ratelimit" {
  count                    = var.enable_ratelimit && ! var.enable_appmesh ? 1 : 0
  family                   = "roxprox-ratelimit"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-ratelimit-task-role[0].arn
  cpu                      = var.ratelimit_cpu
  memory                   = var.ratelimit_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = templatefile("${path.module}/templates/roxprox-ratelimit.json.tmpl", local.ratelimit_config_vars)
}

resource "aws_ecs_task_definition" "roxprox-ratelimit-appmesh" {
  count                    = var.enable_ratelimit && var.enable_appmesh ? 1 : 0
  family                   = "roxprox-ratelimit"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-ratelimit-task-role[0].arn
  cpu                      = var.ratelimit_cpu
  memory                   = var.ratelimit_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = templatefile("${path.module}/templates/roxprox-ratelimit.json.tmpl", local.ratelimit_config_vars)

  proxy_configuration {
    type           = "APPMESH"
    container_name = "envoy"
    properties = {
      AppPorts         = "8080"
      EgressIgnoredIPs = "169.254.170.2,169.254.169.254"
      IgnoredUID       = "1337"
      ProxyEgressPort  = 15001
      ProxyIngressPort = 15000
    }
  }
}

resource "aws_ecs_service" "roxprox-ratelimit" {
  count           = var.enable_ratelimit ? 1 : 0
  name            = "roxprox-ratelimit"
  cluster         = aws_ecs_cluster.roxprox.id
  desired_count   = var.ratelimit_count
  task_definition = var.enable_appmesh ? aws_ecs_task_definition.roxprox-ratelimit-appmesh[0].arn : aws_ecs_task_definition.roxprox-ratelimit[0].arn

  launch_type = "FARGATE"

  network_configuration {
    subnets          = var.subnets
    security_groups  = [aws_security_group.roxprox-ratelimit[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.roxprox-ratelimit.arn
  }
}
