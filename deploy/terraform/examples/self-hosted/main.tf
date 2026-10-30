# A self-hosted Nightfix control plane in your own AWS account: copy this
# directory, set the variables (terraform.tfvars), configure a backend, and
# apply. Everything runs in your account; nothing calls back to Nightfix.
#
#   1. terraform apply                       (creates everything; tasks start
#                                             once an image is rolled out)
#   2. deploy/scripts/rollout.sh <image> <commit>  (from the release notes:
#                                             verifies the signed release,
#                                             copies it into your ECR, runs
#                                             migrations, rolls it out)
#   3. deploy/scripts/create-org.sh "Acme" acme
#   4. for sign-in, set oidc (with the new org's id) and apply again, then
#      roll out once more so the service picks it up
#   5. deploy the agent (../agent, or the Helm chart) pointed at agent_endpoint
#
# The scripts read this directory's outputs: run them with
# NIGHTFIX_TF_DIR=<this directory>.

terraform {
  required_version = ">= 1.11"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.90"
    }
  }
  # backend "s3" { ... }   # keep state in your account, with locking
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { app = "nightfix", environment = var.environment, managed_by = "terraform" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "domain" {
  description = "A zone you control, e.g. ops.example.com. The control plane uses api., ingest. and agent. under it."
  type        = string
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone for var.domain. Empty: create the records from the dns_records and acm_validation_records outputs yourself."
  type        = string
  default     = ""
}

variable "existing_vpc" {
  description = "Use an existing VPC (two public subnets for the load balancers, two private subnets with NAT). Null creates one."
  type = object({
    vpc_id             = string
    public_subnet_ids  = list(string)
    private_subnet_ids = list(string)
  })
  default = null
}

variable "alarm_email" {
  description = "Where the control plane's own alarms go."
  type        = string
  default     = ""
}

variable "oidc" {
  description = "User sign-in through your identity provider (Okta, Google Workspace, Entra ID, Keycloak, Auth0…); see the module's oidc variable. Null: API keys only."
  type = object({
    issuer               = string
    audience             = string
    client_ids           = list(string)
    org_id               = string
    allowed_groups       = optional(list(string), [])
    email_domains        = optional(list(string), [])
    required_claims      = optional(map(string), {})
    email_claim          = optional(string, "")
    groups_claim         = optional(string, "")
    email_verified_claim = optional(string, "")
    trust_email          = optional(bool, false)
  })
  default = null
}

module "control_plane" {
  source = "../../modules/nightfix-control-plane"
  # When copying this example out of the repository, pin the module to a
  # release: source = "github.com/peacedouts/nightfix//deploy/terraform/modules/nightfix-control-plane?ref=<commit>"

  environment     = var.environment
  domain          = var.domain
  route53_zone_id = var.route53_zone_id
  existing_vpc    = var.existing_vpc
  alarm_email     = var.alarm_email
  oidc            = var.oidc
  # Two tasks and a Multi-AZ database once people depend on it.
  desired_count = 2
  db_multi_az   = true
}

output "api_url" {
  value = module.control_plane.api_url
}

output "ingest_url" {
  value = module.control_plane.ingest_url
}

output "agent_endpoint" {
  value = module.control_plane.agent_endpoint
}

output "dns_records" {
  value = module.control_plane.dns_records
}

output "acm_validation_records" {
  value = module.control_plane.acm_validation_records
}

output "admin_task" {
  value = module.control_plane.admin_task
}

output "rollout" {
  value = module.control_plane.rollout
}

output "alarm_topic_arn" {
  value = module.control_plane.alarm_topic_arn
}
