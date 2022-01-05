resource "aws_cloudwatch_log_group" "roxprox" {
  name = "roxprox"
  kms_key_id = var.cloudwatch_logs_kms
}

