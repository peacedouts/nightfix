variable "name_prefix" {
  description = "Prefix for resource names. Resources are named <name_prefix>-<environment>."
  type        = string
  default     = "nightfix"
  validation {
    # With environment, it has to fit load balancer and target group names (32 characters).
    condition     = can(regex("^[a-z][a-z0-9-]{0,10}[a-z0-9]$", var.name_prefix)) && !strcontains(var.name_prefix, "--")
    error_message = "name_prefix must be 2-12 lowercase letters, digits or single hyphens, starting with a letter and not ending with a hyphen."
  }
}

variable "environment" {
  description = "Name of this deployment, used in resource names (e.g. prod, staging)."
  type        = string
  default     = "prod"
  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,8}[a-z0-9])?$", var.environment)) && !strcontains(var.environment, "--")
    error_message = "environment must be 1-10 lowercase letters, digits or single hyphens, starting with a letter and not ending with a hyphen."
  }
}

# --- Hostnames and DNS -------------------------------------------------------

variable "domain" {
  description = "DNS zone the three hostnames live under (e.g. ops.example.com)."
  type        = string
}

variable "api_hostname" {
  description = "Host for the REST API and Slack callbacks."
  type        = string
  default     = "api"
}

variable "ingest_hostname" {
  description = "Host alert sources (CloudWatch via SNS, webhooks) send to."
  type        = string
  default     = "ingest"
}

variable "agent_hostname" {
  description = "Host agents connect to (mutual TLS, passed straight through to the tasks)."
  type        = string
  default     = "agent"
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone for var.domain. When set, the module creates the certificate validation records and the three host records. When empty, create the records in your DNS from the dns_records and acm_validation_records outputs (DNS only: no proxying, which would break the agents' mutual TLS)."
  type        = string
  default     = ""
}

# --- Image ------------------------------------------------------------------

variable "image" {
  description = "Control-plane image for the first apply, pinned by digest (<repository>@sha256:<digest>). Empty uses the ECR repository this module creates, at var.image_tag. Later rollouts go through deploy/scripts/rollout.sh (or the deploy workflow), not Terraform."
  type        = string
  default     = ""
  validation {
    condition     = var.image == "" || can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by digest (<repository>@sha256:<64 hex digits>)."
  }
}

variable "image_tag" {
  description = "Tag in this module's ECR repository for the first apply, used when var.image is empty."
  type        = string
  default     = "latest"
}

# --- Network ----------------------------------------------------------------

variable "existing_vpc" {
  description = "Deploy into an existing VPC instead of creating one. Public subnets hold only the load balancers; private subnets (with outbound internet through NAT) hold the tasks and the database. At least two of each, in different AZs."
  type = object({
    vpc_id             = string
    public_subnet_ids  = list(string)
    private_subnet_ids = list(string)
  })
  default = null
  validation {
    condition     = var.existing_vpc == null || (length(var.existing_vpc.public_subnet_ids) >= 2 && length(var.existing_vpc.private_subnet_ids) >= 2)
    error_message = "existing_vpc needs at least two public and two private subnets."
  }
}

variable "vpc_cidr" {
  description = "CIDR for the VPC this module creates (ignored with existing_vpc)."
  type        = string
  default     = "10.40.0.0/16"
}

variable "single_nat_gateway" {
  description = "One NAT gateway for all AZs (cheaper; an AZ outage then cuts outbound traffic). Set false for one per AZ. Ignored with existing_vpc."
  type        = bool
  default     = true
}

variable "agent_ingress_cidrs" {
  description = "Where agents may connect from. Agents authenticate with mutual TLS, so the default is anywhere; narrow it to the NAT addresses of the VPCs your agents run in when you know them."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ingest_ingress_cidrs" {
  description = "Where the API and alert ingest may be reached from. SNS and Slack call from AWS and Slack address ranges, so the default is anywhere."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# --- Database ---------------------------------------------------------------

variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "db_multi_az" {
  description = "Standby in a second AZ. Recommended once people depend on it."
  type        = bool
  default     = false
}

variable "db_allocated_storage" {
  description = "Initial storage in GiB; autoscales up to 5x."
  type        = number
  default     = 20
}

variable "db_performance_insights" {
  description = "Performance Insights. Not available on every instance class (check before enabling on db.t4g.small)."
  type        = bool
  default     = false
}

# --- Service ----------------------------------------------------------------

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
  description = "Auth0 tenant domain (e.g. example.us.auth0.com). Empty disables user login (API keys only)."
  type        = string
  default     = ""
}

variable "auth0_client_ids" {
  description = "With auth0_domain: the client IDs of Nightfix's applications in the tenant. Tokens issued to any other application (which can usually get one for the same API) are refused."
  type        = list(string)
  default     = []
  validation {
    condition     = var.auth0_domain == "" || length(var.auth0_client_ids) > 0
    error_message = "auth0_client_ids is required with auth0_domain."
  }
}

variable "auth0_audience" {
  description = "Auth0 API identifier. Empty means https://<api host>."
  type        = string
  default     = ""
}

variable "oidc" {
  description = <<-EOT
    User sign-in through any OpenID Connect provider (instead of Auth0): every
    user of the issuer belongs to the org org_id (create it first, with
    create-org.sh). issuer is exactly as the provider's tokens carry it, e.g.
    https://acme.okta.com/oauth2/default, https://accounts.google.com, or
    https://login.microsoftonline.com/<tenant id>/v2.0; audience is the API
    identifier or client ID the tokens are issued for; client_ids are Nightfix's
    application(s) there (tokens issued to any other application are refused).
    Say who may sign in with at least one of allowed_groups (any one),
    email_domains, or required_claims (claim = value, all must match); with
    Google, required_claims must pin hd to your Workspace domain. trust_email:
    count a token with no email-verified claim as verified (prefer
    email_verified_claim, e.g. Entra's xms_edov).
  EOT
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
  validation {
    condition     = var.oidc == null || can(regex("^https://", var.oidc.issuer))
    error_message = "oidc.issuer must be an https URL."
  }
  validation {
    condition     = var.oidc == null || var.auth0_domain == ""
    error_message = "Set auth0_domain or oidc, not both."
  }
  validation {
    condition     = var.oidc == null || length(var.oidc.client_ids) > 0
    error_message = "oidc.client_ids must name Nightfix's application in your identity provider."
  }
  validation {
    condition     = var.oidc == null || length(var.oidc.allowed_groups) + length(var.oidc.email_domains) + length(var.oidc.required_claims) > 0
    error_message = "Say who may sign in: oidc.allowed_groups, oidc.email_domains or oidc.required_claims."
  }
}

variable "alarm_email" {
  description = "Where CloudWatch alarms go. Empty creates the SNS topic without a subscription (subscribe it to your own pager)."
  type        = string
  default     = ""
}

variable "deletion_protection" {
  description = "Protect the database, load balancers, image repository and secrets from deletion. Set false only for a sandbox you will tear down: it also skips the final DB snapshot and lets destroy empty the image repository."
  type        = bool
  default     = true
}

# --- Bring your own ------------------------------------------------------------
# Each of these replaces something the module would otherwise create, for an
# account that already has it (or a policy that says where it must come from).

variable "certificate_arn" {
  description = "An existing ACM certificate (in this region) covering the API and ingest hosts, e.g. a wildcard for var.domain. Empty creates and validates one."
  type        = string
  default     = ""
}

variable "existing_database" {
  description = <<-EOT
    Use an existing PostgreSQL 16+ server instead of creating an RDS instance.
    admin_secret_arn is a Secrets Manager secret whose JSON has a "password"
    key, for admin_username: a login that can create roles and owns the
    database (migrations create nfx_owner and nfx_app). The server must accept
    TLS with a certificate the RDS global bundle verifies (RDS and Aurora do),
    and security_group_id is the server's security group: the module adds a
    rule letting the control-plane tasks reach it. db_instance_identifier, if
    set, gets the CPU and storage alarms.
  EOT
  type = object({
    host                   = string
    port                   = optional(number, 5432)
    name                   = string
    admin_username         = string
    admin_secret_arn       = string
    security_group_id      = string
    db_instance_identifier = optional(string, "")
    admin_secret_kms_key   = optional(string, "") # if the secret uses a customer managed key
  })
  default = null
}

variable "sealing_kms_key_arn" {
  description = "An existing KMS key to wrap the credential-sealing key. Its key policy must let this account's IAM policies grant use (the default key policy does). Empty creates one."
  type        = string
  default     = ""
}

variable "data_kms_key_arn" {
  description = "An existing KMS key for RDS storage, snapshots and Performance Insights. Empty creates one. Ignored with existing_database."
  type        = string
  default     = ""
}

variable "alarm_topic_arn" {
  description = "An existing SNS topic for the control plane's own alarms (e.g. one your pager already subscribes to). Empty creates one."
  type        = string
  default     = ""
}

variable "iam_role_path" {
  description = "Path for every IAM role the module creates."
  type        = string
  default     = "/"
}

variable "iam_permissions_boundary_arn" {
  description = "Permissions boundary attached to every IAM role the module creates, where your account requires one."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Retention for the control plane's logs (VPC flow and RDS logs keep 30 days)."
  type        = number
  default     = 90
}

variable "logs_kms_key_arn" {
  description = "KMS key to encrypt the module's CloudWatch log groups. Its key policy must allow the CloudWatch Logs service in this region. Empty uses CloudWatch's default encryption."
  type        = string
  default     = ""
}

variable "db_backup_retention_days" {
  description = "Automated backup retention for the RDS instance the module creates."
  type        = number
  default     = 14
}

variable "app_db_password_version" {
  description = "Bump to generate a new password for the nfx_app database role; then roll out again, which sets it (see deploy/README.md, Operating it)."
  type        = number
  default     = 1
}

variable "existing_ecs_cluster_arn" {
  description = "Run in an existing ECS cluster (Fargate capacity) instead of creating one."
  type        = string
  default     = ""
}

variable "container_insights" {
  description = "Container Insights on the cluster the module creates (more metrics, extra CloudWatch cost). With existing_ecs_cluster_arn, say whether that cluster has it instead. The running-tasks alarm is created only when this is true, because without Insights its metric never arrives and the alarm would always fire."
  type        = bool
  default     = true
}

variable "vpc_endpoints" {
  description = "Create interface endpoints for KMS, STS, Secrets Manager, ECR and CloudWatch Logs, and an S3 gateway endpoint, so the control plane's AWS calls don't need NAT. Slack, PagerDuty, SNS certificates and your identity provider still need outbound HTTPS. Only for the VPC this module creates: in an existing VPC, their private DNS would redirect every other workload's AWS calls to endpoints that only admit Nightfix (use the VPC's own endpoints there)."
  type        = bool
  default     = false
  validation {
    condition     = !var.vpc_endpoints || var.existing_vpc == null
    error_message = "vpc_endpoints is only for the VPC this module creates; with existing_vpc, use the VPC's own endpoints."
  }
}

variable "waf_web_acl_arn" {
  description = "An existing WAFv2 web ACL (regional) to attach to the API and ingest load balancer. Its rules must let SNS deliveries and Slack callbacks through."
  type        = string
  default     = ""
}

variable "log_subscription" {
  description = "Stream the control plane's logs to your SIEM: a subscription filter to a Kinesis stream, Firehose or Lambda. role_arn is needed for Kinesis and Firehose."
  type = object({
    destination_arn = string
    role_arn        = optional(string, "")
    filter_pattern  = optional(string, "")
  })
  default = null
}
