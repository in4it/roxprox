output "lb-dns-name" {
  value = aws_lb.lb.dns_name
}

output "lb-zone-id" {
  value = aws_lb.lb.zone_id
}
