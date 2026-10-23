variable "name" {
  description = "Name for the role, service and log group."
  type        = string
  default     = "nightfix-agent"
}

variable "org_id" {
  description = "Your Nightfix org id (org_…)."
  type        = string
}

variable "nightfix_api_url" {
  description = "Nightfix API, used to fetch the agent gateway's CA certificate."
  type        = string
  default     = "https://api.nightfix.dev"
}

variable "agent_endpoint" {
  description = "Nightfix agent gateway."
  type        = string
  default     = "https://agent.nightfix.dev"
}

variable "image" {
  description = <<-EOT
    Agent image, pinned by digest (ghcr.io/peacedouts/nightfix-agent@sha256:…).
    The agent runs under your IAM role and decides what to execute, so
    anything that can change would let a new build reach your account on the
    next task restart. That includes :sha-<commit> tags: registry tags can be
    re-pushed. Verify the digest with cosign before pinning (see the
    deployment guide).
  EOT
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "Pin the agent image by digest (…@sha256:<64 hex>). Registry tags, including :sha-<commit>, can be re-pushed."
  }
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Private subnets with outbound internet (NAT). The agent opens no inbound ports."
  type        = list(string)
}

variable "cluster_arn" {
  description = "Existing ECS cluster to run in. Empty creates one."
  type        = string
  default     = ""
}

variable "desired_count" {
  description = "Agents to run. Two is the production recommendation, so a restart never leaves you without one."
  type        = number
  default     = 2
}

variable "cpu" {
  type    = number
  default = 256
}

variable "memory" {
  type    = number
  default = 512
}

variable "runbook_policy_json" {
  description = "IAM policy for what your runbooks may do, e.g. ecs:DescribeServices and ecs:UpdateService on specific services. Keep it narrow: this is the agent's entire reach."
  type        = string
  default     = ""
}

variable "managed_policy_arns" {
  description = "Extra managed policies to attach to the agent's role."
  type        = list(string)
  default     = []
}

variable "extra_egress" {
  description = "Extra outbound rules beyond HTTPS, for shell steps that reach databases or caches (e.g. { port = 5432, cidr = \"10.0.0.0/16\" })."
  type = list(object({
    port = number
    cidr = string
  }))
  default = []
}

variable "required_signers" {
  description = "Signers every runbook must carry, pinned in the agent itself, each as \"key_id=base64-public-key\" (a bare key_id doesn't pin the key). With your own key here, even a compromised Nightfix can't get new code run in your account."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for s in var.required_signers : can(regex("^[^=,\\s]+=[A-Za-z0-9+/]+={0,2}$", s))])
    error_message = "Each required signer is \"key_id=base64-public-key\" (the agent_pin from GET /v1/signing-keys, split on commas)."
  }
}

variable "ca_pem" {
  description = "Agent gateway CA. Empty fetches it from <nightfix_api_url>/v1/agent-ca.pem over HTTPS."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  type    = number
  default = 30
}
