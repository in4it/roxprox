resource "aws_iam_role" "ecs-task-execution-role" {
  name = "ecs-task-execution-role"

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

resource "aws_iam_role_policy" "ecs-task-execution-role" {
  name = "ecs-task-execution-role"
  role = "${aws_iam_role.ecs-task-execution-role.id}"

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
  role = "${aws_iam_role.roxprox-task-role.id}"

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
    }
  ]
}
EOF
}
