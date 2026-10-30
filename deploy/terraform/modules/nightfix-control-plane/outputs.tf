output "api_url" {
  value = "https://${local.api_host}"
}

output "ingest_url" {
  value = "https://${local.ingest_host}"
}

output "agent_endpoint" {
  description = "NIGHTFIX_ENDPOINT for agents"
  value       = "https://${local.agent_host}"
}

output "dns_records" {
  description = "CNAMEs to create when route53_zone_id is empty: host => target. DNS only, never proxied."
  value       = local.host_records
}

output "acm_validation_records" {
  description = "Certificate validation records to create when route53_zone_id is empty. Apply waits at the certificate validation until they resolve."
  value       = local.acm_validation
}

output "ecr_repository_url" {
  value = aws_ecr_repository.controlplane.repository_url
}

output "admin_task" {
  description = "For deploy/scripts/create-org.sh, link-auth0.sh and new-owner-key.sh"
  value = {
    cluster           = local.cluster_name
    task_definition   = aws_ecs_task_definition.admin.family
    subnets           = join(",", local.private_subnet_ids)
    security_group    = aws_security_group.tasks.id
    region            = local.region
    org_secret_prefix = "${local.name}/org-api-keys/"
  }
}

output "rollout" {
  description = "For deploy/scripts/rollout.sh (and the deploy workflow's repository variables)"
  value = {
    region          = local.region
    ecr_repository  = aws_ecr_repository.controlplane.repository_url
    cluster         = local.cluster_name
    service         = aws_ecs_service.controlplane.name
    service_family  = aws_ecs_task_definition.controlplane.family
    migrate_family  = aws_ecs_task_definition.migrate.family
    admin_family    = aws_ecs_task_definition.admin.family
    private_subnets = join(",", local.private_subnet_ids)
    security_group  = aws_security_group.tasks.id
  }
}

output "deploy_permissions" {
  description = "What a CI deploy role needs to reach (see deploy/terraform/control-plane/github.tf)"
  value = {
    ecr_repository_arn = aws_ecr_repository.controlplane.arn
    cluster_arn        = local.cluster_arn
    service_id         = aws_ecs_service.controlplane.id
    migrate_family     = aws_ecs_task_definition.migrate.family
    pass_role_arns     = [aws_iam_role.execution.arn, aws_iam_role.migrate_execution.arn, aws_iam_role.task.arn, aws_iam_role.admin.arn]
  }
}

output "alarm_topic_arn" {
  description = "SNS topic the control plane's own alarms go to. Subscribe your pager to it."
  value       = local.alarm_topic_arn
}

output "vpc_id" {
  value = local.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnets with outbound internet (the sandbox smoke test runs the agent and demo service in them)"
  value       = local.private_subnet_ids
}
