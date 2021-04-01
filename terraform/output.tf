output "lb-dns-name" {
  value = aws_lb.lb.dns_name
}

output "lb-zone-id" {
  value = aws_lb.lb.zone_id
}

output "lb-arn" {
  value = aws_lb.lb.arn
}

output "lb-arn-suffix" {
  value = aws_lb.lb.arn_suffix
}

output "roxprox-alb-sg" {
  value = aws_security_group.roxprox-alb[0].id
}

output "roxprox-envoy-sg" {
  value = var.loadbalancer == "alb" ? aws_security_group.roxprox-envoy-alb[0].id : aws_security_group.roxprox-envoy-nlb[0].id
}

output "roxprox-kms-arn" {
  value = var.s3_bucket_sse ? aws_kms_key.roxprox-s3-sse-kms[0].arn : ""
}

output "lb-mtls-dns-name" {
  value = element([for lb-mtls in aws_lb.lb-mtls : lb-mtls.dns_name], 0)
}

output "lb-mtls-zone-id" {
  value = element([for lb-mtls in aws_lb.lb-mtls : lb-mtls.zone_id], 0)
}
