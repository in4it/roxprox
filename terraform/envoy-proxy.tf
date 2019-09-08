#
# envoy (http)
#

data "template_file" "envoy-config-http" {
  template = file("${path.module}/envoy.yml")
  vars = {
    CLUSTER = "roxprox"
    ID      = "roxprox-http"
    ADDRESS = "roxprox.roxprox.local"
  }
}

resource "aws_ssm_parameter" "envoy-config-http" {
  name  = "/roxprox/envoy.yaml"
  type  = "String"
  value = base64encode(trimspace(data.template_file.envoy-config-http.rendered))
}


data "template_file" "envoy-proxy" {
  template =  var.enable_appmesh ? file("${path.module}/templates/envoy-appmesh.json.tpl") : file("${path.module}/templates/envoy.json.tpl")

  vars = {
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release
    ENVOY_CONFIG          = aws_ssm_parameter.envoy-config-http.arn
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    EXTRA_CONTAINERS      = var.extra_containers == "" ? "" : ",${var.extra_containers}"
    EXTRA_DEPENDENCY      = var.extra_dependency == "" ? "" : ",${var.extra_dependency}"
  }
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
  container_definitions    = data.template_file.envoy-proxy.rendered
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
  container_definitions    = data.template_file.envoy-proxy.rendered

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
    subnets = var.subnets
    security_groups = var.loadbalancer == "alb" ? [aws_security_group.roxprox-envoy-alb[0].id] : [aws_security_group.roxprox-envoy-nlb[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.roxprox-envoy.arn
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.envoy-proxy-http.id
    container_name = "envoy-proxy"
    container_port = "10000"
  }
}

#
# envoy (https)
#

data "template_file" "envoy-config-https" {
  count = var.tls_listener ? 1 : 0
  template = file("${path.module}/envoy.yml")
  vars = {
    CLUSTER = "roxprox"
    ID = "roxprox-https"
    ADDRESS = "roxprox.roxprox.local"
  }
}

data "template_file" "envoy-proxy-https" {
  count = var.tls_listener ? 1 : 0
  template =  var.enable_appmesh ? file("${path.module}/templates/envoy-appmesh.json.tpl") : file("${path.module}/templates/envoy.json.tpl")

  vars = {
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release
    ENVOY_CONFIG          = aws_ssm_parameter.envoy-config-https[0].arn
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
    EXTRA_CONTAINERS      = var.extra_containers == "" ? "" : ",${var.extra_containers}"
    EXTRA_DEPENDENCY      = var.extra_dependency == "" ? "" : ",${var.extra_dependency}"
  }
}

resource "aws_ssm_parameter" "envoy-config-https" {
  count = var.tls_listener ? 1 : 0
  name = "/roxprox/envoy-https.yaml"
  type = "String"
  value = base64encode(trimspace(data.template_file.envoy-config-https[0].rendered))
}

resource "aws_ecs_task_definition" "envoy-proxy-https" {
  count                    = var.tls_listener ? 1 : 0
  family                   = "envoy-proxy-https"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-envoy-proxy-task-role.arn
  cpu                      = var.envoy_proxy_cpu
  memory                   = var.envoy_proxy_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions = data.template_file.envoy-proxy-https[0].rendered
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
  container_definitions    = data.template_file.envoy-proxy-https[0].rendered

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
}

