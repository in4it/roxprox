variable "envoy_release" {
  description = "docker tag of envoy release"
  default     = "v1.10.0"
}

variable "release" {
  description = "roxprox release"
}

variable "acme_contact" {
  default     = ""
  description = "email address to be used for ACME - Let's encrypt will use this to notify you of expiring domains"
}

variable "control_plane_count" {
  description = "number of control plane instances to run"
  default     = 1
}

variable "envoy_proxy_count" {
  description = "number of envoy proxies to run"
  default     = 1
}

variable "subnets" {
  type        = list(string)
  description = "subnets to use"
}

variable "lb_subnets" {
  type        = list(string)
  description = "loadbalancer subnets to use"
}

variable "s3_bucket" {
  description = "name of s3 bucket to use"
}

variable "envoy_autocert_loglevel" {
  description = "log level"
  default     = "info"
}

variable "loadbalancer" {
  description = "loadbalancer type to use"
  default     = "nlb"
}

variable "loadbalancer_alb_cert" {
  description = "loadbalancer alb certificate to use"
  default     = ""
}
variable "loadbalancer_ssl_policy" {
  description = "ssl policy for the https listener to use"
  default     = "ELBSecurityPolicy-2016-08"
}
variable "loadbalancer_https_forwarding" {
  description = "if true, redirect all http traffic to https"
  default     = false
}

variable "tls_listener" {
  description = "run a service for a tls (https) listener (true/false)"
  type        = bool
}

variable "management_access_sg" {
  description = "allow access to the management interface"
  type        = list
  default     = []
}