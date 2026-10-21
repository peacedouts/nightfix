data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# --- KMS -------------------------------------------------------------------

# Wraps the key that seals per-org credentials (Slack, PagerDuty, webhook
# secrets) and the agent CA. The control plane creates that data key with
# GenerateDataKey on its first start; only ciphertext is ever stored.
resource "aws_kms_key" "sealing" {
  description             = "Nightfix ${var.environment}: wraps the credential-sealing key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "sealing" {
  # The control plane records this name with the wrapped key, so keep it stable.
  name          = "alias/${local.name}-sealing"
  target_key_id = aws_kms_key.sealing.key_id
}

resource "aws_kms_key" "data" {
  description             = "Nightfix ${var.environment}: RDS storage and snapshots"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# --- Postgres ----------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "main" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  # Slow queries are logged and exported to CloudWatch; keep bind parameters
  # (emails, alert payloads) out of those logs.
  parameter {
    name  = "log_parameter_max_length"
    value = "0"
  }
  parameter {
    name  = "log_parameter_max_length_on_error"
    value = "0"
  }
}

resource "aws_db_instance" "main" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 5
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.data.arn

  db_name  = "nightfix"
  username = "nightfix_admin"
  # RDS creates and rotates the master password in Secrets Manager. It's used
  # only by the migrate task; the app connects as nfx_app.
  manage_master_user_password = true

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.main.name
  publicly_accessible    = false
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  backup_retention_period         = 14
  copy_tags_to_snapshot           = true
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${local.name}-final"
  auto_minor_version_upgrade      = true
  performance_insights_enabled    = var.db_performance_insights
  performance_insights_kms_key_id = var.db_performance_insights ? aws_kms_key.data.arn : null
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

# nfx_app's password. Generated ephemerally and written write-only, so it
# never appears in Terraform state or plans. The migrate task sets it on the
# role; the service reads it to connect. Bump the version to rotate.
ephemeral "random_password" "app_db" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "app_db" {
  name                    = "${local.name}/db-app-password"
  description             = "Password for the nfx_app database role"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "app_db" {
  secret_id                = aws_secretsmanager_secret.app_db.id
  secret_string_wo         = ephemeral.random_password.app_db.result
  secret_string_wo_version = 1
}

# --- Container registry ------------------------------------------------------

resource "aws_ecr_repository" "controlplane" {
  name                 = "nightfix/controlplane"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "controlplane" {
  repository = aws_ecr_repository.controlplane.name
  policy = jsonencode({
    # Only untagged leftovers expire. Tagged images (one per commit, plus
    # signatures and SBOMs) are kept, so a rollback or a task replacement can
    # always pull the image that's running.
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 14 }
      action       = { type = "expire" }
    }]
  })
}
