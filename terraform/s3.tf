locals {
  s3_server_side_encryption_configuration_rules = var.s3_bucket_sse ? [
    {
      kms_master_key_id = aws_kms_key.roxprox-s3-sse-kms[0].arn
      sse_algorithm     = "aws:kms"
    }
  ] : []
}


resource "aws_s3_bucket" "roxprox" {
  bucket = var.s3_bucket
  acl    = "private"
  dynamic "server_side_encryption_configuration" {
    for_each = local.s3_server_side_encryption_configuration_rules
    content {
      rule {
        apply_server_side_encryption_by_default {
          kms_master_key_id = server_side_encryption_configuration.value.kms_master_key_id
          sse_algorithm     = server_side_encryption_configuration.value.sse_algorithm
        }
      }
    }
  }

  policy = <<EOF
{
  "Id": "S3Policy",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSSLRequestsOnly",
      "Action": "s3:*",
      "Effect": "Deny",
      "Resource": [
        "arn:aws:s3:::${var.s3_bucket}",
        "arn:aws:s3:::${var.s3_bucket}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      },
      "Principal": "*"
    }
  ]
}
EOF
}

resource "aws_s3_bucket_public_access_block" "roxprox" {
  bucket = aws_s3_bucket.roxprox.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

}

resource "aws_s3_bucket_notification" "roxprox-notification" {
  bucket = aws_s3_bucket.roxprox.id

  queue {
    queue_arn     = aws_sqs_queue.roxprox-notifications.arn
    events        = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    filter_suffix = ".yaml"
  }
}

resource "aws_sqs_queue" "roxprox-notifications" {
  name                       = "${var.s3_bucket}-notifications"
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = 30
  message_retention_seconds  = 60

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"  
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:${var.s3_bucket}-notifications",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.roxprox.arn}" }
      }
    }
  ]
}
POLICY
}
