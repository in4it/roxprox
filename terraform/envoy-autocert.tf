resource "aws_ecs_cluster" "envoy-autocert" {
  name = "envoy-autocert"
}
resource "aws_ecs_task_definition" "envoy-autocert" {
  family                   = "envoy-autocert"
  execution_role_arn       = "${aws_iam_role.ecs-task-execution-role.arn}"
  task_role_arn            = "${aws_iam_role.envoy-autocert-task-role.arn}"
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  container_definitions = <<DEFINITION
[
  {
    "essential": true,
    "image": "in4it/envoy-autocert:${var.release}",
    "name": "envoy-autocert",
    "command": ["-acme-contact", "${var.acme_contact}", "-storage-type", "s3", "-storage-bucket", "${var.s3_bucket}", "-aws-region", "${data.aws_region.current.name}", "-loglevel", "${var.envoy_autocert_loglevel}"],
    "logConfiguration": { 
            "logDriver": "awslogs",
            "options": { 
               "awslogs-group" : "envoy-autocert",
               "awslogs-region": "${data.aws_region.current.name}",
               "awslogs-stream-prefix": "envoy-autocert"
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

resource "aws_ecs_service" "envoy-autocert" {
  name            = "envoy-autocert"
  cluster         = "${aws_ecs_cluster.envoy-autocert.id}"
  desired_count   = "${var.control_plane_count}"
  task_definition = "${aws_ecs_task_definition.envoy-autocert.arn}"
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = ["${var.subnets}"]
    security_groups  = ["${aws_security_group.envoy-autocert.id}"]
    assign_public_ip = true
  }

  service_registries {
    registry_arn = "${aws_service_discovery_service.envoy-autocert.arn}"
  }
}
