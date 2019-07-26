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

resource "aws_ecs_task_definition" "envoy-proxy" {
  family                   = "envoy-proxy"
  execution_role_arn       = aws_iam_role.roxprox-ecs-task-execution-role.arn
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  container_definitions = <<DEFINITION
[
  {
    "essential": true,
    "image": "envoyproxy/envoy:${var.envoy_release}",
    "name": "envoy-proxy",
    "entryPoint": ["bash"],
    "command": ["-c", "echo 'IyEvYmluL2Jhc2gKcHJpbnRmICIlcyIgJEVOVk9ZX0NPTkZJRyB8YmFzZTY0IC0tZGVjb2RlID4gL2V0Yy9lbnZveS9lbnZveS55YW1sCmVudm95IC0tY29uZmlnLXBhdGggL2V0Yy9lbnZveS9lbnZveS55YW1sCg==' |base64 --decode |bash"],
    "logConfiguration": { 
            "logDriver": "awslogs",
            "options": { 
               "awslogs-group" : "roxprox",
               "awslogs-region": "${data.aws_region.current.name}",
               "awslogs-stream-prefix": "envoy-proxy"
            }
     },
		 "secrets": [
       { 
         "name": "ENVOY_CONFIG", 
         "valueFrom": "${aws_ssm_parameter.envoy-config-http.arn}"
       }
     ],
     "portMappings": [ 
        { 
           "containerPort": 10000,
           "hostPort": 10000,
           "protocol": "tcp"
        },
        { 
           "containerPort": 10001,
           "hostPort": 10001,
           "protocol": "tcp"
        }
     ]
  }
]
DEFINITION

}

resource "aws_ecs_service" "envoy-proxy" {
  name = "envoy-proxy"
  cluster = aws_ecs_cluster.roxprox.id
  desired_count = var.envoy_proxy_count
  task_definition = aws_ecs_task_definition.envoy-proxy.arn
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

resource "aws_ssm_parameter" "envoy-config-https" {
  count = var.tls_listener ? 1 : 0
  name = "/roxprox/envoy-https.yaml"
  type = "String"
  value = base64encode(trimspace(data.template_file.envoy-config-https[0].rendered))
}

resource "aws_ecs_task_definition" "envoy-proxy-https" {
  count = var.tls_listener ? 1 : 0
  family = "envoy-proxy-https"
  execution_role_arn = aws_iam_role.roxprox-ecs-task-execution-role.arn
  cpu = 256
  memory = 512
  network_mode = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  container_definitions = <<DEFINITION
[
  {
    "essential": true,
    "image": "envoyproxy/envoy:${var.envoy_release}",
    "name": "envoy-proxy-https",
    "entryPoint": ["bash"],
    "command": ["-c", "echo 'IyEvYmluL2Jhc2gKcHJpbnRmICIlcyIgJEVOVk9ZX0NPTkZJRyB8YmFzZTY0IC0tZGVjb2RlID4gL2V0Yy9lbnZveS9lbnZveS55YW1sCmVudm95IC0tY29uZmlnLXBhdGggL2V0Yy9lbnZveS9lbnZveS55YW1sCg==' |base64 --decode |bash"],
    "logConfiguration": { 
            "logDriver": "awslogs",
            "options": { 
               "awslogs-group" : "roxprox",
               "awslogs-region": "${data.aws_region.current.name}",
               "awslogs-stream-prefix": "envoy-proxy-https"
            }
     },
		 "secrets": [
       { 
         "name": "ENVOY_CONFIG", 
         "valueFrom": "${aws_ssm_parameter.envoy-config-https[0].arn}"
       }
     ],
     "portMappings": [ 
        { 
           "containerPort": 10000,
           "hostPort": 10000,
           "protocol": "tcp"
        },
        { 
           "containerPort": 10001,
           "hostPort": 10001,
           "protocol": "tcp"
        }
     ]
  }
]
DEFINITION

}

resource "aws_ecs_service" "envoy-proxy-https" {
  count           = var.tls_listener ? 1 : 0
  name            = "envoy-proxy-https"
  cluster         = aws_ecs_cluster.roxprox.id
  desired_count   = var.envoy_proxy_count
  task_definition = aws_ecs_task_definition.envoy-proxy-https[0].arn
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

