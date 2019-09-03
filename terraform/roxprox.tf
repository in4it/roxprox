resource "aws_ecs_cluster" "roxprox" {
  name = "roxprox"
}

data "template_file" "roxprox" {
  template =  var.enable_appmesh ? file("${path.module}/templates/roxprox-appmesh.json") : file("${path.module}/templates/roxprox.json")

  vars = {
    AWS_REGION            = data.aws_region.current.name
    ENVOY_RELEASE         = var.envoy_release        
    LOGLEVEL              = var.envoy_autocert_loglevel
    ACME_CONTACT          = var.acme_contact
    S3_BUCKET             = var.s3_bucket
    APPMESH_NAME          = var.appmesh_name
    APPMESH_ENVOY_RELEASE = var.appmesh_envoy_release
  }
}

resource "aws_ecs_task_definition" "roxprox" {
  count                    = var.enable_appmesh ? 0 : 1
  family                   = "roxprox"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-task-role.arn
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    =  data.template_file.roxprox.rendered

}
resource "aws_ecs_task_definition" "roxprox-appmesh" {
  count                    = var.enable_appmesh ? 1 : 0
  family                   = "roxprox"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-task-role.arn
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    =  data.template_file.roxprox.rendered

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

# service if type is alb/nlb
resource "aws_ecs_service" "roxprox" {
  name = "roxprox"
  cluster = aws_ecs_cluster.roxprox.id
  desired_count = var.control_plane_count
  task_definition = var.enable_appmesh ? aws_ecs_task_definition.roxprox-appmesh[0].arn : aws_ecs_task_definition.roxprox[0].arn

  launch_type = "FARGATE"

  network_configuration {
    subnets = var.subnets
    security_groups = [aws_security_group.roxprox.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.roxprox.arn
  }
}


