# A service for demonstrating Nightfix on real AWS: an ECS service that
# reports itself unhealthy a few minutes after it starts, a CloudWatch alarm
# on that, and the SNS topic that delivers the alarm to Nightfix.
#
# A forced new deployment (what the ecs-service-restart runbook does) starts
# a fresh, healthy task, so the alarm clears: the incident auto-remediates
# and nobody is paged. With heal_on_restart = false every task starts broken,
# so the restart doesn't help and on-call is paged (the demo-fail story).
#
# No image to build: the task runs a few lines of Python on the public
# python image and logs one JSON line every 10 seconds. A metric filter turns
# those lines into a metric with ClusterName and ServiceName dimensions,
# which become the alert's labels (alert.labels.cluster / .service).
#
#   1. Create the Nightfix integration first, pinned to this topic:
#        POST /v1/integrations {"type":"cloudwatch", "default_service":"checkout-api",
#          "topic_arn":"arn:aws:sns:<region>:<account>:nightfix-demo-alarms"}
#   2. terraform apply -var vpc_id=… -var 'subnet_ids=[…]' -var ingest_url=<the integration's ingest_url>
#
# Nightfix confirms the SNS subscription itself once it has verified the
# signature. See deploy/aws-smoke-test.md for the whole run.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Private subnets with a NAT gateway (the task pulls a public image)"
  type        = list(string)
}

variable "ingest_url" {
  description = "The CloudWatch integration's ingest_url from Nightfix (https://ingest…/v1/i/int_…)"
  type        = string
}

variable "cluster_name" {
  description = "Must be one the agent's role may act on (examples/agent: ecs_cluster_name)"
  type        = string
  default     = "prod-east"
}

variable "service_name" {
  description = "Also the Nightfix service the runbook's trigger lists"
  type        = string
  default     = "checkout-api"
}

variable "break_after_seconds" {
  description = "How long a new task reports healthy before it reports unhealthy"
  type        = number
  default     = 300
}

variable "heal_on_restart" {
  description = "false: every task starts unhealthy, so a restart doesn't fix it (on-call gets paged)"
  type        = bool
  default     = true
}

locals {
  topic_name = "nightfix-demo-alarms"
  script     = <<-PY
    import json, os, time
    start = time.time()
    after = int(os.environ["BREAK_AFTER"])
    heal = os.environ["HEAL_ON_RESTART"] == "true"
    while True:
        bad = (not heal) or time.time() - start > after
        print(json.dumps({"cluster": os.environ["CLUSTER"], "service": os.environ["SERVICE"], "unhealthy": 1 if bad else 0}), flush=True)
        time.sleep(10)
  PY
}

resource "aws_ecs_cluster" "demo" {
  name = var.cluster_name
}

resource "aws_cloudwatch_log_group" "demo" {
  name              = "/nightfix-demo/${var.service_name}"
  retention_in_days = 7
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "nightfix-demo-execution"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "demo" {
  name   = "nightfix-demo"
  vpc_id = var.vpc_id
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_task_definition" "demo" {
  family                   = "nightfix-demo-${var.service_name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn

  container_definitions = jsonencode([{
    name      = "app"
    image     = "public.ecr.aws/docker/library/python:3.12-alpine"
    essential = true
    command   = ["python", "-c", local.script]
    environment = [
      { name = "CLUSTER", value = var.cluster_name },
      { name = "SERVICE", value = var.service_name },
      { name = "BREAK_AFTER", value = tostring(var.break_after_seconds) },
      { name = "HEAL_ON_RESTART", value = tostring(var.heal_on_restart) },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.demo.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "app"
      }
    }
  }])
}

resource "aws_ecs_service" "demo" {
  name            = var.service_name
  cluster         = aws_ecs_cluster.demo.id
  task_definition = aws_ecs_task_definition.demo.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.demo.id]
    assign_public_ip = false
  }
  # The runbook forces new deployments; Terraform shouldn't undo them.
  lifecycle {
    ignore_changes = [task_definition]
  }
}

resource "aws_cloudwatch_log_metric_filter" "unhealthy" {
  name           = "nightfix-demo-unhealthy"
  log_group_name = aws_cloudwatch_log_group.demo.name
  pattern        = "{ $.unhealthy = * }"
  metric_transformation {
    namespace = "NightfixDemo"
    name      = "Unhealthy"
    value     = "$.unhealthy"

    dimensions = {
      ClusterName = "$.cluster"
      ServiceName = "$.service"
    }
  }
}

resource "aws_sns_topic" "alarms" {
  name = local.topic_name
}

# Nightfix confirms the subscription itself after verifying its signature.
resource "aws_sns_topic_subscription" "nightfix" {
  topic_arn              = aws_sns_topic.alarms.arn
  protocol               = "https"
  endpoint               = var.ingest_url
  endpoint_auto_confirms = true
}

# The example runbook's trigger matches alarm names starting "ecs-unhealthy-".
resource "aws_cloudwatch_metric_alarm" "unhealthy" {
  alarm_name          = "ecs-unhealthy-${var.service_name}"
  alarm_description   = "Demo: ${var.service_name} reports itself unhealthy"
  namespace           = "NightfixDemo"
  metric_name         = "Unhealthy"
  dimensions          = { ClusterName = var.cluster_name, ServiceName = var.service_name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

output "topic_arn" {
  value = aws_sns_topic.alarms.arn
}

output "cluster" {
  value = aws_ecs_cluster.demo.name
}

output "service" {
  value = aws_ecs_service.demo.name
}
