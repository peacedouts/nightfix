data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "http" "ca" {
  count = var.ca_pem == "" ? 1 : 0
  url   = "${trimsuffix(var.nightfix_api_url, "/")}/v1/agent-ca.pem"
  lifecycle {
    postcondition {
      condition     = self.status_code == 200 && startswith(self.response_body, "-----BEGIN CERTIFICATE-----")
      error_message = "Couldn't fetch the agent CA from ${var.nightfix_api_url}/v1/agent-ca.pem."
    }
  }
}

locals {
  ca_pem      = var.ca_pem != "" ? var.ca_pem : data.http.ca[0].response_body
  cluster_arn = var.cluster_arn != "" ? var.cluster_arn : aws_ecs_cluster.agent[0].arn
}

resource "aws_ecs_cluster" "agent" {
  count = var.cluster_arn == "" ? 1 : 0
  name  = var.name
}

resource "aws_cloudwatch_log_group" "agent" {
  name              = "/nightfix/${var.name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# The agent's identity. Nightfix enrolls the agent by verifying it holds this
# role (no tokens), and every runbook step runs with exactly these
# permissions, nothing more.
resource "aws_iam_role" "agent" {
  name               = var.name
  path               = "/nightfix/"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "runbooks" {
  count  = var.runbook_policy_json == "" ? 0 : 1
  name   = "runbooks"
  role   = aws_iam_role.agent.id
  policy = var.runbook_policy_json
}

resource "aws_iam_role_policy_attachment" "extra" {
  for_each   = toset(var.managed_policy_arns)
  role       = aws_iam_role.agent.name
  policy_arn = each.value
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  path               = "/nightfix/"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Outbound only. No ingress rules at all.
resource "aws_security_group" "agent" {
  name        = var.name
  description = "Nightfix agent: outbound only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.agent.id
  description       = "Nightfix gateway, AWS APIs, Secrets Manager"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "extra" {
  for_each          = { for i, r in var.extra_egress : "${r.port}-${r.cidr}" => r }
  security_group_id = aws_security_group.agent.id
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_ecs_task_definition" "agent" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.agent.arn

  volume {
    name = "tmp" # scratch space for shell steps; the root filesystem is read-only
  }

  container_definitions = jsonencode([{
    name                   = "agent"
    image                  = var.image
    essential              = true
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp" }]
    environment = [
      { name = "NIGHTFIX_ENDPOINT", value = var.agent_endpoint },
      { name = "NIGHTFIX_ORG_ID", value = var.org_id },
      { name = "NIGHTFIX_ENROLL_METHOD", value = "iam" },
      { name = "NIGHTFIX_CA_PEM", value = local.ca_pem },
      { name = "NIGHTFIX_REQUIRED_SIGNERS", value = join(",", var.required_signers) },
      { name = "AWS_REGION", value = data.aws_region.current.name },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.agent.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "agent"
      }
    }
  }])
}

resource "aws_ecs_service" "agent" {
  name            = var.name
  cluster         = local.cluster_arn
  task_definition = aws_ecs_task_definition.agent.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.agent.id]
    assign_public_ip = false
  }
}
