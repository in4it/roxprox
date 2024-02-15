resource "aws_cloudwatch_log_group" "roxprox" {
  name              = "roxprox"
  kms_key_id        = var.cloudwatch_logs_kms
  retention_in_days = var.cloudwatch_log_retention_period
}

