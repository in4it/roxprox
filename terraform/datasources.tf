data "aws_region" "current" {}

data "aws_subnet" "subnet" {
  id = "${element(var.subnets, 0)}"
}

