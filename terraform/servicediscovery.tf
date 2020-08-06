resource "aws_service_discovery_private_dns_namespace" "roxprox" {
  name        = "roxprox.local"
  description = "roxprox.local"
  vpc         = data.aws_subnet.subnet.vpc_id
}

resource "aws_service_discovery_service" "roxprox" {
  name = "roxprox"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.roxprox.id

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

resource "aws_service_discovery_service" "roxprox-envoy" {
  name = "envoy"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.roxprox.id

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

resource "aws_service_discovery_service" "roxprox-datadog" {
  name = "datadog"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.roxprox.id

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

resource "aws_service_discovery_service" "roxprox-ratelimit" {
  count = var.enable_ratelimit ? 1 : 0
  name  = replace(var.ratelimit_address, ".roxprox.local", "")

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.roxprox.id

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