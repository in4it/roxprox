resource "aws_appmesh_virtual_node" "envoy-proxy" {
  count     = var.enable_appmesh ? 1 : 0
  name      = "envoy-proxy"
  mesh_name = "${var.appmesh_name}"

  spec {
    listener {
      port_mapping {
        port     = 10000
        protocol = "tcp"
      }

      backend {
        dynamic "virtual_service" {
          for_each = var.appmesh_backends:
            content {
              virtual_service_name = virtual_service.value
            }
      }

      health_check {
        protocol            = "tcp"
        healthy_threshold   = 2
        unhealthy_threshold = 2
        timeout_millis      = 2000
        interval_millis     = 30000
      }
    }

    service_discovery {
      dns {
        hostname = "envoy.roxprox.local"
      }
    }
  }
}

resource "aws_appmesh_virtual_service" "envoy-proxy" {
  count     = var.enable_appmesh ? 1 : 0
  name      = "envoy.roxprox.local"
  mesh_name = "${var.appmesh_name}"

  spec {
    provider {
      virtual_node {
        virtual_node_name = "${aws_appmesh_virtual_node.envoy-proxy[0].name}"
      }
    }
  }
}


resource "aws_appmesh_virtual_node" "roxprox" {
  count     = var.enable_appmesh ? 1 : 0
  name      = "roxprox"
  mesh_name = "${var.appmesh_name}"

  spec {
    listener {
      port_mapping {
        port     = 8080
        protocol = "tcp"
      }

      health_check {
        protocol            = "tcp"
        healthy_threshold   = 2
        unhealthy_threshold = 2
        timeout_millis      = 2000
        interval_millis     = 30000
      }
    }

    service_discovery {
      dns {
        hostname = "roxprox.roxprox.local"
      }
    }
  }
}

resource "aws_appmesh_virtual_service" "roxprox" {
  count     = var.enable_appmesh ? 1 : 0
  name      = "roxprox.roxprox.local"
  mesh_name = "${var.appmesh_name}"

  spec {
    provider {
      virtual_node {
        virtual_node_name = "${aws_appmesh_virtual_node.roxprox[0].name}"
      }
    }
  }
}