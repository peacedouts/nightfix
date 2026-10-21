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
  description = "Host for the REST API and Slack callbacks."
  type        = string
  default     = "api"
}

variable "ingest_hostname" {
  description = "Host customers point alert integrations at."
  type        = string
  default     = "ingest"
}

variable "agent_hostname" {
  description = "Host agents connect to (mutual TLS, passed straight through to the tasks)."
  type        = string
  default     = "agent"
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
  description = "One NAT gateway for all AZs (cheaper; an AZ outage then cuts outbound traffic). Set false for one per AZ."
  type        = bool
  default     = true
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "db_multi_az" {
  description = "Standby in a second AZ. Recommended once customers depend on it."
  type        = bool
  default     = false
}

variable "db_allocated_storage" {
  description = "Initial storage in GiB; autoscales up to 5x."
  type        = number
  default     = 20
}

variable "desired_count" {
  description = "Control-plane tasks. Two or more: workers coordinate through Postgres, so any number can run."
  type        = number
  default     = 2
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
  description = "Auth0 tenant domain (e.g. nightfix.us.auth0.com). Empty disables user login (API keys only)."
  type        = string
  default     = ""
}

variable "auth0_audience" {
  description = "Auth0 API identifier."
  type        = string
  default     = "https://api.nightfix.dev"
}

variable "github_repository" {
  description = "owner/repo allowed to push images and deploy through GitHub OIDC."
  type        = string
  default     = "peacedouts/nightfix"
}

variable "alarm_email" {
  description = "Where CloudWatch alarms go. Empty creates the SNS topic without a subscription."
  type        = string
  default     = ""
}

variable "db_performance_insights" {
  description = "Performance Insights. Not available on every instance class (check before enabling on db.t4g.small)."
  type        = bool
  default     = false
}
