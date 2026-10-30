variable "region" {
  description = "AWS region for the control plane."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Name of this deployment, used in resource names (e.g. prod, staging)."
  type        = string
  default     = "prod"
}

variable "domain" {
  description = "Cloudflare zone the service lives under."
  type        = string
  default     = "nightfix.dev"
}

variable "api_hostname" {
  type    = string
  default = "api"
}

variable "ingest_hostname" {
  type    = string
  default = "ingest"
}

variable "agent_hostname" {
  type    = string
  default = "agent"
}

variable "image_tag" {
  description = "Control-plane image tag for the first apply. Later rollouts go through the deploy workflow."
  type        = string
  default     = "latest"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "single_nat_gateway" {
  type    = bool
  default = true
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "db_multi_az" {
  type    = bool
  default = false
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "db_performance_insights" {
  type    = bool
  default = false
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "task_cpu" {
  type    = number
  default = 512
}

variable "task_memory" {
  type    = number
  default = 1024
}

variable "auth0_domain" {
  description = "Auth0 tenant domain. Empty disables user login (API keys only)."
  type        = string
  default     = ""
}

variable "auth0_client_ids" {
  description = "With auth0_domain: the client IDs of Nightfix's applications in the Auth0 tenant."
  type        = list(string)
  default     = []
}

variable "auth0_audience" {
  type    = string
  default = "https://api.nightfix.dev"
}

variable "alarm_email" {
  type    = string
  default = ""
}

variable "deletion_protection" {
  description = "Set false only for a sandbox you will tear down."
  type        = bool
  default     = true
}

variable "github_repository" {
  description = "owner/repo allowed to push images and deploy through GitHub OIDC."
  type        = string
  default     = "peacedouts/nightfix"
}

variable "github_oidc_provider_arn" {
  description = "ARN of an existing GitHub Actions OIDC provider in this account. Empty creates one; set it for a second environment in the same account (the provider is account-wide)."
  type        = string
  default     = ""
}
