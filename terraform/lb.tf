#
# roxprox ALB/NLB
#

# alb domain cert
data "aws_acm_certificate" "alb_cert" {
  count    = var.loadbalancer == "alb" ? 1 : 0
  domain   = var.loadbalancer_alb_cert
  statuses = ["ISSUED"]
}

data "aws_acm_certificate" "alb_cert_extra" {
  count    = length(var.loadbalancer_alb_cert_extra)
  domain   = element(var.loadbalancer_alb_cert_extra, count.index)
  statuses = ["ISSUED"]
}

resource "aws_lb" "lb" {
  name               = "roxprox"
  subnets            = var.lb_subnets
  load_balancer_type = var.loadbalancer == "alb" ? "application" : "network"
  security_groups    = var.loadbalancer == "alb" ? [aws_security_group.roxprox-alb[0].id] : []

  access_logs {
    bucket  = var.bucket_lb_logs
    prefix  = "roxprox-lb"
    enabled = var.enable_lb_logs
  }

  enable_deletion_protection = true
}

resource "aws_lb" "lb-mtls" {
  count              = length(var.mtls)
  name               = "roxprox-mtls"
  subnets            = var.lb_subnets
  load_balancer_type = "network"

  access_logs {
    bucket  = var.bucket_lb_logs
    prefix  = "roxprox-lb-mtls"
    enabled = var.enable_lb_logs
  }

  enable_deletion_protection = true
}

# lb listener (https)
resource "aws_lb_listener" "lb-https" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "443"
  protocol          = var.loadbalancer == "alb" ? "HTTPS" : "TCP"
  certificate_arn   = var.loadbalancer == "alb" ? data.aws_acm_certificate.alb_cert[0].arn : ""
  ssl_policy        = var.loadbalancer_ssl_policy

  default_action {
    target_group_arn = var.tls_listener ? aws_lb_target_group.envoy-proxy-https[0].id : aws_lb_target_group.envoy-proxy-http.id
    type             = "forward"
  }
}

resource "aws_lb_listener" "lb-mtls" {
  count             = length(var.mtls)
  load_balancer_arn = aws_lb.lb-mtls[count.index].arn
  port              = "443"
  protocol          = "TCP"

  default_action {
    target_group_arn = aws_lb_target_group.envoy-proxy-mtls[count.index].id
    type             = "forward"
  }
}

resource "aws_lb_listener_certificate" "extra-certificates" {
  count           = length(var.loadbalancer_alb_cert_extra)
  listener_arn    = aws_lb_listener.lb-https.arn
  certificate_arn = element(data.aws_acm_certificate.alb_cert_extra.*.arn, count.index)
}

resource "aws_lb_listener_rule" "lb-https-redirect" {
  count        = var.loadbalancer_https_forwarding ? 1 : 0
  listener_arn = aws_lb_listener.lb-http.arn
  priority     = 1

  action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  condition {
    path_pattern {
      values = ["/*"]
    }
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
    matcher             = var.loadbalancer == "alb" ? var.loadbalancer_healthcheck_matcher : ""
    path                = var.loadbalancer == "alb" ? var.loadbalancer_healthcheck_path : ""
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
    protocol            = var.loadbalancer == "alb" ? "HTTP" : "TCP"
    interval            = 30
  }
}

resource "aws_lb_target_group" "envoy-proxy-mtls" {
  count                = length(var.mtls)
  name                 = "envoy-proxy-mtls"
  port                 = var.mtls[count.index].port
  protocol             = "TCP"
  target_type          = "ip"
  vpc_id               = data.aws_subnet.subnet.vpc_id


  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    protocol            = "TCP"
    interval            = 30
  }
}
