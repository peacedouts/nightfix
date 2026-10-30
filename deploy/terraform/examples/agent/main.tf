# A complete agent install: restart a named ECS service in your account.
#
#   terraform init && terraform apply -var org_id=org_… -var vpc_id=vpc-… -var 'subnet_ids=["subnet-…","subnet-…"]' \
#     -var agent_image=ghcr.io/peacedouts/nightfix-agent@sha256:…
#
# Then register the output role ARN with Nightfix (see deploy/README.md).

terraform {
  required_version = ">= 1.9"
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

variable "required_signers" {
  description = "Pin the org's signing key in the agent: the agent_pin from GET /v1/signing-keys, split on commas. Empty trusts the control plane's list."
  type        = list(string)
  default     = []
}

variable "nightfix_api_url" {
  description = "Nightfix API: the control plane's api_url output (https://api.<domain>)"
  type        = string
}

variable "agent_endpoint" {
  description = "Nightfix agent gateway: the control plane's agent_endpoint output (https://agent.<domain>)"
  type        = string
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
  required_signers = var.required_signers

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
