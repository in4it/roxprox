resource "aws_s3_bucket" "envoy-autocert" {
  bucket = "${var.s3_bucket}"
  acl    = "private"
}
