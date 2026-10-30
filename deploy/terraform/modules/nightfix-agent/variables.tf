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
  description = "Nightfix API (https://api.<your domain>, the control plane's api_url), used to fetch the agent gateway's CA certificate when ca_pem is empty."
  type        = string
  validation {
    condition     = can(regex("^https://[^/]+$", var.nightfix_api_url))
    error_message = "nightfix_api_url is https://<host>, with no path."
  }
}

variable "agent_endpoint" {
  description = "Nightfix agent gateway (https://agent.<your domain>, the control plane's agent_endpoint)."
  type        = string
  validation {
    condition     = can(regex("^https://[^/]+$", var.agent_endpoint))
    error_message = "agent_endpoint is https://<host>, with no path."
  }
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
  description = "Signers every runbook must carry, pinned in the agent itself, each as \"key_id=base64-public-key\" (a bare key_id doesn't pin the key). Pin the org's signing key (agent_pin from GET /v1/signing-keys) and the agent refuses runbooks signed by any other key, whatever the control plane's key list says later. Co-signing with a key you hold isn't built yet: a key the control plane can't sign with makes the agent refuse every runbook."
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

variable "iam_role_path" {
  description = "Path for the agent's IAM roles. (Enrollment rules match the role by account and name; the path doesn't matter.)"
  type        = string
  default     = "/nightfix/"
}

variable "iam_permissions_boundary_arn" {
  description = "Permissions boundary attached to the agent's IAM roles, where your account requires one. The boundary must allow what runbooks do (runbook_policy_json, managed_policy_arns)."
  type        = string
  default     = ""
}

variable "logs_kms_key_arn" {
  description = "KMS key to encrypt the agent's log group. Its key policy must allow the CloudWatch Logs service in this region. Empty uses CloudWatch's default encryption."
  type        = string
  default     = ""
}

variable "allowlist_mode" {
  description = "Local runbook allowlist: off, warn (log runbooks that aren't on it) or enforce (refuse them). Use enforce in production: publishing a runbook otherwise runs its code on every matching agent, so anyone who can publish can run code under this role."
  type        = string
  default     = "off"
  validation {
    condition     = contains(["off", "warn", "enforce"], var.allowlist_mode)
    error_message = "allowlist_mode is off, warn or enforce."
  }
}

variable "allowlist_yaml" {
  description = <<-EOT
    The allowlist (YAML) for allowlist_mode warn or enforce. Pin each runbook
    by digest; version numbers aren't signed:

      runbooks:
        - name: restart-api
          digest: sha256:…
        - name: scale-workers
          version: "*"   # every version, still signature-checked
  EOT
  type        = string
  default     = ""
  validation {
    condition     = var.allowlist_mode == "off" || trimspace(var.allowlist_yaml) != ""
    error_message = "Set allowlist_yaml when allowlist_mode is warn or enforce."
  }
}

variable "step_types" {
  description = "Step types this agent may run (shell, aws, wait). Empty allows all. Leave out shell where runbooks only need AWS calls: shell steps run arbitrary commands under this role."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for t in var.step_types : contains(["shell", "aws", "wait"], t)])
    error_message = "step_types are shell, aws or wait."
  }
}
