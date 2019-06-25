#
# roxprox ALB/NLB
#

# alb domain cert
data "aws_acm_certificate" "alb_cert" {
  count    = var.loadbalancer == "alb" ? 1 : 0
  domain   = var.loadbalancer_alb_cert
  statuses = ["ISSUED"]
}

resource "aws_lb" "lb" {
  name               = "roxprox"
  subnets            = var.subnets
  load_balancer_type = var.loadbalancer == "alb" ? "application" : "network"

  enable_deletion_protection = true
}

# lb listener (https)
resource "aws_lb_listener" "lb-https" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "443"
  protocol          = var.loadbalancer == "alb" ? "HTTPS" : "TCP"
  certificate_arn   = var.loadbalancer == "alb" ? data.aws_acm_certificate.alb_cert[0].arn : ""

  default_action {
    target_group_arn = var.tls_listener ? aws_lb_target_group.envoy-proxy-https[0].id : aws_lb_target_group.envoy-proxy-http.id
    type             = "forward"
  }
}

# lb listener (http)
resource "aws_lb_listener" "lb-http" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "80"
  protocol          = var.loadbalancer == "alb" ? "HTTP" : "TCP"

  default_action {
    target_group_arn = aws_lb_target_group.envoy-proxy-http.id
    type             = "forward"
  }
}

resource "aws_lb_target_group" "envoy-proxy-http" {
  name                 = "envoy-proxy-http"
  port                 = "10000"
  protocol             = var.loadbalancer == "alb" ? "HTTP" : "TCP"
  target_type          = "ip"
  vpc_id               = data.aws_subnet.subnet.vpc_id
  deregistration_delay = "30"
  slow_start           = "30"

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    protocol            = var.loadbalancer == "alb" ? "HTTP" : "TCP"
    matcher             = var.loadbalancer == "alb" ? "200,404,301,302" : ""
    interval            = 30
  }
}

resource "aws_lb_target_group" "envoy-proxy-https" {
  count                = var.tls_listener ? 1 : 0
  name                 = "envoy-proxy-https"
  port                 = "10001"
  protocol             = var.loadbalancer == "alb" ? "HTTP" : "TCP"
  target_type          = "ip"
  vpc_id               = data.aws_subnet.subnet.vpc_id
  deregistration_delay = "30"
  slow_start           = "30"


  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    protocol            = "TCP"
    interval            = 30
  }
}

