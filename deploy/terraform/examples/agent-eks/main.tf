# The IAM side of a Nightfix agent on EKS, for the Helm chart in
# deploy/helm/nightfix-agent: a role that is the agent's identity (it enrolls
# by proving it) and its entire reach, given to the chart's service account
# through EKS Pod Identity.
#
#   terraform apply
#   helm install nightfix-agent deploy/helm/nightfix-agent -n nightfix --create-namespace \
#     --set image.digest=sha256:… --set nightfix.endpoint=https://agent.ops.example.com \
#     --set nightfix.orgId=org_… --set aws.region=us-east-1 --set-file nightfix.caPem=agent-ca.pem
#
# Then register an enrollment rule for role_arn (see the chart's notes).
#
# Anyone who can run a pod as this service account in this namespace can act
# as the agent: keep the namespace to the agent, and its RBAC to the people
# who deploy it.
#
# IRSA instead of Pod Identity: drop the association, trust the cluster's
# OIDC provider (sts:AssumeRoleWithWebIdentity, with the sub condition
# system:serviceaccount:<namespace>:<service account>), and set the chart's
# serviceAccount.annotations."eks.amazonaws.com/role-arn" to the role.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.90"
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

variable "cluster_name" {
  description = "The EKS cluster (with the EKS Pod Identity Agent add-on installed)."
  type        = string
}

variable "namespace" {
  type    = string
  default = "nightfix"
}

variable "service_account" {
  description = "The chart's service account: <release>-nightfix-agent, or serviceAccount.name."
  type        = string
  default     = "nightfix-agent"
}

variable "iam_permissions_boundary_arn" {
  type    = string
  default = ""
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "agent" {
  name                 = "nightfix-agent-eks"
  path                 = "/nightfix/"
  permissions_boundary = var.iam_permissions_boundary_arn != "" ? var.iam_permissions_boundary_arn : null
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Condition = {
        StringEquals = {
          "aws:SourceAccount"                         = data.aws_caller_identity.current.account_id
          "aws:RequestTag/kubernetes-namespace"       = var.namespace
          "aws:RequestTag/kubernetes-service-account" = var.service_account
        }
      }
    }]
  })
}

# The agent's entire reach. Keep it to what your runbooks call (see the
# notes on ecs:UpdateService in deploy/README.md).
resource "aws_iam_role_policy" "runbooks" {
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:DescribeServices", "ecs:UpdateService"]
      Resource = "arn:aws:ecs:${var.region}:${data.aws_caller_identity.current.account_id}:service/prod-east/*"
    }]
  })
}

resource "aws_eks_pod_identity_association" "agent" {
  cluster_name    = var.cluster_name
  namespace       = var.namespace
  service_account = var.service_account
  role_arn        = aws_iam_role.agent.arn
}

output "role_arn" {
  description = "Register an enrollment rule for this role"
  value       = aws_iam_role.agent.arn
}
