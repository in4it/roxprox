#
# envoy-autocert NLB
#
resource "aws_lb" "lb" {
  name            = "envoy-autocert"
  subnets         = ["${var.subnets}"]
  load_balancer_type = "network"

  enable_deletion_protection = true
}

# lb listener (https)
resource "aws_lb_listener" "lb-https" {
  load_balancer_arn = "${aws_lb.lb.arn}"
  port              = "443"
  protocol          = "TCP"

  default_action {
    target_group_arn = "${aws_lb_target_group.envoy-proxy-https.id}"
    type             = "forward"
  }
}

# lb listener (http)
resource "aws_lb_listener" "lb-http" {
  load_balancer_arn = "${aws_lb.lb.arn}"
  port              = "80"
  protocol          = "TCP"

  default_action {
    target_group_arn = "${aws_lb_target_group.envoy-proxy-http.id}"
    type             = "forward"
  }
}


resource "aws_lb_target_group" "envoy-proxy-http" {
  name                 = "envoy-proxy-http"
  port                 = "10000"
  protocol             = "TCP"
  target_type          = "ip"
  vpc_id               = "${data.aws_subnet.subnet.vpc_id}"
  deregistration_delay = "30"
  slow_start           = "30"

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    protocol            = "TCP"
    interval            = 30
  }
  stickiness = []
}

resource "aws_lb_target_group" "envoy-proxy-https" {
  name                 = "envoy-proxy-https"
  port                 = "10001"
  protocol             = "TCP"
  target_type          = "ip"
  vpc_id               = "${data.aws_subnet.subnet.vpc_id}"
  deregistration_delay = "30"
  slow_start           = "30"

  stickiness = []

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    protocol            = "TCP"
    interval            = 30
  }
}

