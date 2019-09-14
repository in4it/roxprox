#
# datadog integration
#
data "template_file" "datadog" {
  count    = var.enable_datadog ? 1 : 0
  template = file("${path.module}/templates/datadog-agent.json.tpl")

  vars = {
    AWS_REGION = data.aws_region.current.name
    DD_API_KEY = var.datadog_api_key
    DD_APM_ENV = var.datadog_env
    STATS_URL  = var.datadog_stats_url
    IMAGE      = var.datadog_image
    VERSION    = var.datadog_image_version
  }
}

resource "aws_ecs_task_definition" "datadog" {
  count                    = var.enable_datadog ? 1 : 0
  family                   = "datadog-fargate"
  execution_role_arn       = aws_iam_role.datadog-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.datadog-task-role.arn
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = data.template_file.datadog[0].rendered
}

resource "aws_ecs_service" "datadog" {
  count           = var.enable_datadog ? 1 : 0
  name            = "datadog"
  cluster         = aws_ecs_cluster.roxprox.id
  desired_count   = var.datadog_count
  task_definition = aws_ecs_task_definition.datadog[0].arn

  launch_type = "FARGATE"

  network_configuration {
    subnets          = var.subnets
    security_groups  = [aws_security_group.roxprox-datadog[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.roxprox-datadog.arn
  }
}
