resource "aws_ecs_cluster" "roxprox" {
  name = "roxprox"
}

resource "aws_ecs_task_definition" "roxprox" {
  family                   = "roxprox"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  task_role_arn            = aws_iam_role.roxprox-task-role.arn
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  container_definitions = <<DEFINITION
[
  {
    "essential": true,
    "image": "in4it/roxprox:${var.release}",
    "name": "roxprox",
    "command": ["-acme-contact", "${var.acme_contact}", "-storage-path", "/config", "-storage-type", "s3", "-storage-bucket", "${var.s3_bucket}", "-aws-region", "${data.aws_region.current.name}", "-loglevel", "${var.envoy_autocert_loglevel}"],
    "logConfiguration": { 
            "logDriver": "awslogs",
            "options": { 
               "awslogs-group" : "roxprox",
               "awslogs-region": "${data.aws_region.current.name}",
               "awslogs-stream-prefix": "roxprox"
            }
     },
     "portMappings": [ 
        { 
           "containerPort": 8080,
           "hostPort": 8080,
           "protocol": "tcp"
        }
     ]
  }
]
DEFINITION

}

# service if type is alb/nlb
resource "aws_ecs_service" "roxprox" {
  #count    = var.loadbalancer == "alb" ? 0 : 1
  name = "roxprox"
  cluster = aws_ecs_cluster.roxprox.id
  desired_count = var.control_plane_count
  task_definition = aws_ecs_task_definition.roxprox.arn
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


