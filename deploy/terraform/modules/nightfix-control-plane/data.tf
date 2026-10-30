data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# --- KMS -------------------------------------------------------------------

# Wraps the key that seals per-org credentials (Slack, PagerDuty, webhook
# secrets) and the agent CA. The control plane creates that data key with
# GenerateDataKey on its first start; only ciphertext is ever stored.
resource "aws_kms_key" "sealing" {
  count                   = local.create_sealing_key ? 1 : 0
  description             = "Nightfix ${local.name}: wraps the credential-sealing key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "sealing" {
  count = local.create_sealing_key ? 1 : 0
  # The control plane records this name with the wrapped key, so keep it stable.
  name          = "alias/${local.name}-sealing"
  target_key_id = aws_kms_key.sealing[0].key_id
}

resource "aws_kms_key" "data" {
  count                   = local.create_data_key ? 1 : 0
  description             = "Nightfix ${local.name}: RDS storage and snapshots"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# --- Postgres ----------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  count      = local.create_db ? 1 : 0
  name       = local.name
  subnet_ids = local.private_subnet_ids
}

resource "aws_db_parameter_group" "main" {
  count  = local.create_db ? 1 : 0
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
  count          = local.create_db ? 1 : 0
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 5
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = local.data_key_arn

  db_name  = "nightfix"
  username = "nightfix_admin"
  # RDS creates and rotates the master password in Secrets Manager. It's used
  # only by the migrate task; the app connects as nfx_app.
  manage_master_user_password = true

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.main[0].name
  vpc_security_group_ids = [aws_security_group.db[0].id]
  parameter_group_name   = aws_db_parameter_group.main[0].name
  publicly_accessible    = false
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  backup_retention_period         = var.db_backup_retention_days
  copy_tags_to_snapshot           = true
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = !var.deletion_protection
  final_snapshot_identifier       = var.deletion_protection ? "${local.name}-final" : null
  auto_minor_version_upgrade      = true
  performance_insights_enabled    = var.db_performance_insights
  performance_insights_kms_key_id = var.db_performance_insights ? local.data_key_arn : null
  enabled_cloudwatch_logs_exports = ["postgresql"]

  # RDS would otherwise create the export log group itself, with no
  # retention, and leave it behind on destroy.
  depends_on = [aws_cloudwatch_log_group.rds]
}

resource "aws_cloudwatch_log_group" "rds" {
  count             = local.create_db ? 1 : 0
  name              = "/aws/rds/instance/${local.name}/postgresql"
  retention_in_days = 30
  kms_key_id        = local.logs_kms_key_arn
}

# nfx_app's password. Generated ephemerally and written write-only, so it
# never appears in Terraform state or plans. The migrate task sets it on the
# role; the service reads it to connect. Bump app_db_password_version to rotate.
ephemeral "random_password" "app_db" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "app_db" {
  name                    = "${local.name}/db-app-password"
  description             = "Password for the nfx_app database role"
  recovery_window_in_days = var.deletion_protection ? 7 : 0
}

resource "aws_secretsmanager_secret_version" "app_db" {
  secret_id                = aws_secretsmanager_secret.app_db.id
  secret_string_wo         = ephemeral.random_password.app_db.result
  secret_string_wo_version = var.app_db_password_version
}

# --- Container registry ------------------------------------------------------

resource "aws_ecr_repository" "controlplane" {
  name                 = "${local.name}/controlplane"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = !var.deletion_protection
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
