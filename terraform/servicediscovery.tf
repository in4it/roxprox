resource "aws_service_discovery_private_dns_namespace" "envoy-autocert" {
  name        = "envoy-autocert.local"
  description = "envoy-autocert.local"
  vpc         = "${data.aws_subnet.subnet.vpc_id}"
}

resource "aws_service_discovery_service" "envoy-autocert" {
  name = "envoy-autocert"

  dns_config {
    namespace_id = "${aws_service_discovery_private_dns_namespace.envoy-autocert.id}"

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}
