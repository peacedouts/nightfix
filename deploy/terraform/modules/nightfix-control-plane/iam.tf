data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Used by ECS itself: pull the image, write logs, inject secrets.
resource "aws_iam_role" "execution" {
  name                 = "${local.name}-execution"
  path                 = var.iam_role_path
  permissions_boundary = local.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.app_db.arn]
    }]
  })
}

# Only the migrate task can be handed the RDS master password: a task
# definition registered with the service's execution role can't inject it.
resource "aws_iam_role" "migrate_execution" {
  name                 = "${local.name}-migrate-execution"
  path                 = var.iam_role_path
  permissions_boundary = local.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "migrate_execution" {
  role       = aws_iam_role.migrate_execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# An existing database's admin secret encrypted with a customer managed key.
resource "aws_iam_role_policy" "migrate_execution_secret_key" {
  count = local.db_admin_secret_kms != "" ? 1 : 0
  role  = aws_iam_role.migrate_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["kms:Decrypt"]
      Resource  = [local.db_admin_secret_kms]
      Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${local.region}.amazonaws.com" } }
    }]
  })
}

resource "aws_iam_role_policy" "migrate_execution_secrets" {
  role = aws_iam_role.migrate_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.app_db.arn, local.db_admin_secret_arn]
    }]
  })
}

# Used by the control plane's own code. Note what's absent: nothing here can
# touch any customer account. IAM enrollment needs no permission at all (the
# agent signs the STS request; we only forward it).
resource "aws_iam_role" "task" {
  name                 = "${local.name}-task"
  path                 = var.iam_role_path
  permissions_boundary = local.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "task" {
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.sealing.json
}

data "aws_iam_policy_document" "sealing" {
  statement {
    sid       = "SealingKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [local.sealing_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:service"
      values   = ["nightfix"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:purpose"
      values   = ["credential-sealing"]
    }
  }
}

# One-off admin commands (`nightfix org create`). Writes each new org's
# owner API key straight into Secrets Manager, so it's never printed or
# logged. Not used by the service.
resource "aws_iam_role" "admin" {
  name                 = "${local.name}-admin"
  path                 = var.iam_role_path
  permissions_boundary = local.permissions_boundary
  assume_role_policy   = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "admin_sealing" {
  role   = aws_iam_role.admin.id
  policy = data.aws_iam_policy_document.sealing.json
}

resource "aws_iam_role_policy" "admin_org_keys" {
  role = aws_iam_role.admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "OrgKeys"
      Effect   = "Allow"
      Action   = ["secretsmanager:CreateSecret", "secretsmanager:PutSecretValue"]
      Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:${local.name}/org-api-keys/*"
    }]
  })
}
