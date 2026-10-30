# GitHub Actions reaches AWS through short-lived OIDC credentials: no AWS keys
# in GitHub. Two roles, so pushing an image never implies rolling it out:
#
#   push    jobs on main: push images to ECR, nothing else (tags never push:
#           anyone with write access can create one)
#   deploy  only jobs in the "production" GitHub environment. Restrict that
#           environment to the main branch and require a reviewer (see
#           ../README.md), or a branch could run an edited workflow in it.
#
# The deploy role can register task definitions and pass the task roles, so
# it can run any code as the control plane. That's inherent to deploying;
# keep the environment's protections on.

locals {
  github_oidc_provider_arn = var.github_oidc_provider_arn != "" ? var.github_oidc_provider_arn : aws_iam_openid_connect_provider.github[0].arn
}

resource "aws_iam_openid_connect_provider" "github" {
  count           = var.github_oidc_provider_arn == "" ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

data "aws_iam_policy_document" "github_push_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/main"]
    }
  }
}

data "aws_iam_policy_document" "github_deploy_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:production"]
    }
  }
}

locals {
  name   = "nightfix-${var.environment}"
  deploy = module.control_plane.deploy_permissions
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_iam_role" "github_push" {
  name                 = "${local.name}-github-push"
  assume_role_policy   = data.aws_iam_policy_document.github_push_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "github_push" {
  role = aws_iam_role.github_push.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRLogin"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages",
          "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart",
        ]
        Resource = local.deploy.ecr_repository_arn
      },
    ]
  })
}

resource "aws_iam_role" "github_deploy" {
  name                 = "${local.name}-github-deploy"
  assume_role_policy   = data.aws_iam_policy_document.github_deploy_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "github_deploy" {
  role = aws_iam_role.github_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRLogin"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        # Resolve the tag to a digest and read its Sigstore signature.
        Sid      = "ReadImages"
        Effect   = "Allow"
        Action   = ["ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource = local.deploy.ecr_repository_arn
      },
      {
        Sid      = "TaskDefinitions"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition"]
        Resource = "*"
      },
      {
        Sid      = "Rollout"
        Effect   = "Allow"
        Action   = ["ecs:UpdateService", "ecs:DescribeServices"]
        Resource = local.deploy.service_id
      },
      {
        Sid      = "Migrate"
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${var.region}:${data.aws_caller_identity.current.account_id}:task-definition/${local.deploy.migrate_family}:*"
        Condition = {
          ArnEquals = { "ecs:cluster" = local.deploy.cluster_arn }
        }
      },
      {
        Sid      = "WatchTasks"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks"]
        Resource = "*"
        Condition = {
          ArnEquals = { "ecs:cluster" = local.deploy.cluster_arn }
        }
      },
      {
        Sid      = "PassTaskRoles"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = local.deploy.pass_role_arns
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
    ]
  })
}
