resource "aws_s3_bucket" "roxprox" {
  bucket = "${var.s3_bucket}"
  acl    = "private"
}
