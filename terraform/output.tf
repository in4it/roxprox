output "lb-dns-name" {
  value = aws_lb.lb.dns_name
}

output "lb-zone-id" {
  value = aws_lb.lb.zone_id
}

output "lb-arn" {
  value = aws_lb.lb.arn
}

output "roxprox-envoy-sg" {
  value = var.loadbalancer == "alb" ? aws_security_group.roxprox-envoy-alb[0].id : aws_security_group.roxprox-envoy-nlb[0].id
}
