resource "aws_iam_role" "roxprox-ecs-task-execution-role" {
  name = "roxprox-ecs-task-execution-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "roxprox-ecs-extra-task-execution-role" {
  count  = var.extra_task_execution_policy == "" ? 0 : 1
  name   = "roxprox-ecs-extra-task-execution-role"
  role   = aws_iam_role.roxprox-ecs-task-execution-role.id
  policy = var.extra_task_execution_policy
}

resource "aws_iam_role_policy" "roxprox-ecs-task-execution-role" {
  name = "roxprox-ecs-task-execution-role"
  role = aws_iam_role.roxprox-ecs-task-execution-role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "ssm:GetParameters",
        "ssm:GetParameter"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": [
        "arn:aws:ecr:${data.aws_region.current.name}:111345817488:repository/aws-appmesh-envoy",
        "arn:aws:ecr:us-east-1:709825985650:repository/in4it/roxprox"
      ]
    },
    {
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_role" "roxprox-task-role" {
  name = "roxprox-task-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "roxprox-task-role" {
  name = "roxprox-task-role"
  role = aws_iam_role.roxprox-task-role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:Put*"
      ],
      "Resource": "${aws_s3_bucket.roxprox.arn}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "${aws_s3_bucket.roxprox.arn}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:Get*",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage"
      ],
      "Resource": "${aws_sqs_queue.roxprox-notifications.arn}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "aws-marketplace:RegisterUsage"
      ],
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_kms_key" "roxprox-s3-sse-kms" {
  count                   = var.s3_bucket_sse ? 1 : 0
  description             = "roxprox-s3-sse-kms"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "roxprox-s3-sse-kms" {
  count         = var.s3_bucket_sse ? 1 : 0
  name          = "alias/roxprox-s3-sse-kms"
  target_key_id = aws_kms_key.roxprox-s3-sse-kms[0].key_id
}

resource "aws_iam_role_policy" "roxprox-s3-sse-kms-task-role" {
  count = var.s3_bucket_sse ? 1 : 0
  name  = "roxprox-s3-sse-kms-task-role"
  role  = aws_iam_role.roxprox-task-role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
     {
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GenerateDataKey*",
        "kms:Encrypt",
        "kms:ReEncrypt*",
        "kms:Decrypt"
      ],
      "Resource": [
        "${aws_kms_key.roxprox-s3-sse-kms[0].arn}"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role" "roxprox-envoy-proxy-task-role" {
  name = "roxprox-envoy-proxy-task-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "roxprox-envoy-extra-task-role" {
  count  = var.extra_task_role_policy == "" ? 0 : 1
  name   = "roxprox-extra-task-role"
  role   = aws_iam_role.roxprox-envoy-proxy-task-role.id
  policy = var.extra_task_role_policy
}


#
# datadog
#

resource "aws_iam_role" "datadog-ecs-task-execution-role" {
  name = "datadog-ecs-task-execution-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "datadog-ecs-task-execution-role" {
  name = "datadog-ecs-task-execution-role"
  role = aws_iam_role.datadog-ecs-task-execution-role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "datadog-ecs-extra-task-execution-role" {
  count  = var.datadog_extra_task_execution_policy == "" ? 0 : 1
  name   = "datadog-ecs-extra-task-execution-role"
  role   = aws_iam_role.datadog-ecs-task-execution-role.id
  policy = var.datadog_extra_task_execution_policy
}

resource "aws_iam_role" "datadog-task-role" {
  name = "datadog-task-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "datadog-task-role" {
  name = "datadog-task-role"
  role = aws_iam_role.datadog-task-role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:ListClusters",
        "ecs:ListContainerInstances",
        "ecs:DescribeContainerInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_role" "roxprox-ratelimit-task-role" {
  count = var.enable_ratelimit ? 1 : 0
  name  = "roxprox-ratelimit-task-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "roxprox-ratelimit-task-role" {
  count = var.enable_ratelimit ? 1 : 0
  name  = "roxprox-ratelimit-task-role"
  role  = aws_iam_role.roxprox-ratelimit-task-role[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*"
      ],
      "Resource": "${aws_s3_bucket.roxprox.arn}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "${aws_s3_bucket.roxprox.arn}"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "roxprox-ratelimit-s3-sse-kms-task-role" {
  count = var.s3_bucket_sse && var.enable_ratelimit ? 1 : 0
  name  = "roxprox-ratelimit-s3-sse-kms-task-role"
  role  = aws_iam_role.roxprox-ratelimit-task-role[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
     {
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GenerateDataKey*",
        "kms:Decrypt"
      ],
      "Resource": [
        "${aws_kms_key.roxprox-s3-sse-kms[0].arn}"
      ]
    }
  ]
}
EOF
}
