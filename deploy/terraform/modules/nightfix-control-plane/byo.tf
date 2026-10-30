# What the module creates versus what's brought in (see the "Bring your own"
# variables). Everything else refers to these locals, not to the resources.

locals {
  create_db = var.existing_database == null

  db_host              = local.create_db ? aws_db_instance.main[0].address : var.existing_database.host
  db_port              = local.create_db ? 5432 : var.existing_database.port
  db_name              = local.create_db ? aws_db_instance.main[0].db_name : var.existing_database.name
  db_admin_user        = local.create_db ? aws_db_instance.main[0].username : var.existing_database.admin_username
  db_admin_secret_arn  = local.create_db ? aws_db_instance.main[0].master_user_secret[0].secret_arn : var.existing_database.admin_secret_arn
  db_admin_secret_kms  = local.create_db ? "" : var.existing_database.admin_secret_kms_key
  db_security_group_id = local.create_db ? aws_security_group.db[0].id : var.existing_database.security_group_id
  db_alarm_identifier  = local.create_db ? aws_db_instance.main[0].identifier : var.existing_database.db_instance_identifier

  create_sealing_key = var.sealing_kms_key_arn == ""
  sealing_key_arn    = local.create_sealing_key ? aws_kms_key.sealing[0].arn : var.sealing_kms_key_arn
  # What the control plane records with the wrapped key: keep it stable.
  sealing_key_ref = local.create_sealing_key ? aws_kms_alias.sealing[0].name : var.sealing_kms_key_arn

  create_data_key = local.create_db && var.data_kms_key_arn == ""
  data_key_arn    = local.create_data_key ? aws_kms_key.data[0].arn : var.data_kms_key_arn

  create_alarm_topic = var.alarm_topic_arn == ""
  alarm_topic_arn    = local.create_alarm_topic ? aws_sns_topic.alarms[0].arn : var.alarm_topic_arn

  create_certificate = var.certificate_arn == ""
  certificate_arn    = local.create_certificate ? aws_acm_certificate_validation.public[0].certificate_arn : var.certificate_arn

  logs_kms_key_arn     = var.logs_kms_key_arn != "" ? var.logs_kms_key_arn : null
  permissions_boundary = var.iam_permissions_boundary_arn != "" ? var.iam_permissions_boundary_arn : null
}
