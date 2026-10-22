# A complete agent install: restart a named ECS service in your account.
#
#   terraform init && terraform apply -var org_id=org_… -var vpc_id=vpc-… -var 'subnet_ids=["subnet-…","subnet-…"]' \
#     -var agent_image=ghcr.io/peacedouts/nightfix-agent@sha256:…
#
# Then register the output role ARN with Nightfix (see deploy/README.md).

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

variable "org_id" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "agent_image" {
  description = "Pinned agent image: ghcr.io/peacedouts/nightfix-agent@sha256:… (verify it with cosign first)"
  type        = string
}

variable "ecs_cluster_name" {
  description = "Cluster whose services the example runbook may restart"
  type        = string
  default     = "prod-east"
}

variable "nightfix_api_url" {
  description = "Nightfix API (for a sandbox control plane, its api_url output)"
  type        = string
  default     = "https://api.nightfix.dev"
}

variable "agent_endpoint" {
  description = "Nightfix agent gateway (for a sandbox control plane, its agent_endpoint output)"
  type        = string
  default     = "https://agent.nightfix.dev"
}

data "aws_caller_identity" "current" {}

module "nightfix_agent" {
  source = "../../modules/nightfix-agent"

  org_id           = var.org_id
  image            = var.agent_image
  vpc_id           = var.vpc_id
  subnet_ids       = var.subnet_ids
  nightfix_api_url = var.nightfix_api_url
  agent_endpoint   = var.agent_endpoint

  # Exactly what examples/runbooks/ecs-service-restart.yaml calls, scoped to
  # one cluster's services. The agent can do nothing else in this account.
  runbook_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:DescribeServices", "ecs:UpdateService"]
      Resource = "arn:aws:ecs:${var.region}:${data.aws_caller_identity.current.account_id}:service/${var.ecs_cluster_name}/*"
    }]
  })
}

output "agent_role_arn" {
  value = module.nightfix_agent.role_arn
}
