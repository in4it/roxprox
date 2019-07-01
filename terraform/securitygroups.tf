#
# security groups
#
resource "aws_security_group" "roxprox" {
  name        = "roxprox"
  vpc_id      = data.aws_subnet.subnet.vpc_id
  description = "roxprox"

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = var.loadbalancer == "alb" ? [aws_security_group.roxprox-envoy-alb[0].id] : [aws_security_group.roxprox-envoy-nlb[0].id]
  }
  ingress {
    from_port       = 50051
    to_port         = 50051
    protocol        = "tcp"
    self            = true
    security_groups = var.management_access_sg
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "roxprox-envoy-nlb" {
  count       = var.loadbalancer == "alb" ? 0 : 1
  name        = "roxprox-envoy"
  vpc_id      = data.aws_subnet.subnet.vpc_id
  description = "roxprox envoy proxy"

  ingress {
    from_port   = 10000
    to_port     = 10001
    protocol    = "tcp"
    cidr_blocks = [data.aws_subnet.subnet.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "roxprox-envoy-alb" {
  count       = var.loadbalancer == "alb" ? 1 : 0
  name        = "roxprox-envoy"
  vpc_id      = data.aws_subnet.subnet.vpc_id
  description = "roxprox envoy proxy"

  ingress {
    from_port   = 10000
    to_port     = 10001
    protocol    = "tcp"
    security_groups = [aws_security_group.roxprox-alb[0].id]
  }
    
  ingress {
    from_port       = 9901
    to_port         = 9901
    protocol        = "tcp"
    security_groups = var.management_access_sg
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_security_group" "roxprox-alb" {
  count       = var.loadbalancer == "alb" ? 1 : 0
  name        = "roxprox-alb"
  vpc_id      = data.aws_subnet.subnet.vpc_id
  description = "roxprox-alb"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}