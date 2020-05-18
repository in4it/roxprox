resource "aws_s3_bucket" "roxprox" {
  bucket = var.s3_bucket
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "roxprox" {
  bucket = "${aws_s3_bucket.roxprox.id}"

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
