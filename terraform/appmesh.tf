resource "aws_appmesh_virtual_node" "envoy" {
  count     = var.enable_appmesh ? 1 : 0
  name      = "envoy"
  mesh_name = "${var.appmesh_name}"

  spec {
    backend {
      virtual_service {
        virtual_service_name = "envoy"
      }
    }

    listener {
      port_mapping {
        port     = 10000
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
        hostname = "envoy.roxprox.local"
      }
    }
  }
}

resource "aws_appmesh_virtual_service" "envoy" {
  count     = var.enable_appmesh ? 1 : 0
  name      = "envoy.roxprox.local"
  mesh_name = "${var.appmesh_name}"

  spec {
    provider {
      virtual_node {
        virtual_node_name = "${aws_appmesh_virtual_node.envoy[0].name}"
      }
    }
  }
}