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

output "ecr_repository_url" {
  value = aws_ecr_repository.controlplane.repository_url
}

output "admin_task" {
  description = "For deploy/scripts/create-org.sh"
  value = {
    cluster         = aws_ecs_cluster.main.name
    task_definition = aws_ecs_task_definition.admin.family
    subnets         = join(",", aws_subnet.private[*].id)
    security_group  = aws_security_group.tasks.id
    region          = var.region
  }
}

output "github_variables" {
  description = "Repository variables the image and deploy workflows read"
  value = {
    AWS_REGION           = var.region
    AWS_PUSH_ROLE_ARN    = aws_iam_role.github_push.arn
    AWS_DEPLOY_ROLE_ARN  = aws_iam_role.github_deploy.arn
    ECR_REPOSITORY       = aws_ecr_repository.controlplane.repository_url
    ECS_CLUSTER          = aws_ecs_cluster.main.name
    ECS_SERVICE          = aws_ecs_service.controlplane.name
    ECS_TASK_FAMILY      = aws_ecs_task_definition.controlplane.family
    ECS_MIGRATE_FAMILY   = aws_ecs_task_definition.migrate.family
    ECS_ADMIN_FAMILY     = aws_ecs_task_definition.admin.family
    PRIVATE_SUBNETS      = join(",", aws_subnet.private[*].id)
    TASKS_SECURITY_GROUP = aws_security_group.tasks.id
  }
}

output "vpc_id" {
  description = "The control plane's VPC (the sandbox smoke test runs the agent and demo service in it)"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "Private subnets with a NAT gateway"
  value       = aws_subnet.private[*].id
}
