output "api_url" {
  value = module.control_plane.api_url
}

output "ingest_url" {
  value = module.control_plane.ingest_url
}

output "agent_endpoint" {
  description = "NIGHTFIX_ENDPOINT for agents"
  value       = module.control_plane.agent_endpoint
}

output "ecr_repository_url" {
  value = module.control_plane.ecr_repository_url
}

output "admin_task" {
  description = "For deploy/scripts/create-org.sh"
  value       = module.control_plane.admin_task
}

output "rollout" {
  description = "For deploy/scripts/rollout.sh"
  value       = module.control_plane.rollout
}

output "github_variables" {
  description = "Repository variables the image and deploy workflows read"
  value = {
    AWS_REGION           = module.control_plane.rollout.region
    AWS_PUSH_ROLE_ARN    = aws_iam_role.github_push.arn
    AWS_DEPLOY_ROLE_ARN  = aws_iam_role.github_deploy.arn
    ECR_REPOSITORY       = module.control_plane.rollout.ecr_repository
    ECS_CLUSTER          = module.control_plane.rollout.cluster
    ECS_SERVICE          = module.control_plane.rollout.service
    ECS_TASK_FAMILY      = module.control_plane.rollout.service_family
    ECS_MIGRATE_FAMILY   = module.control_plane.rollout.migrate_family
    ECS_ADMIN_FAMILY     = module.control_plane.rollout.admin_family
    PRIVATE_SUBNETS      = module.control_plane.rollout.private_subnets
    TASKS_SECURITY_GROUP = module.control_plane.rollout.security_group
  }
}

output "alarm_topic_arn" {
  value = module.control_plane.alarm_topic_arn
}

output "vpc_id" {
  description = "The control plane's VPC (the sandbox smoke test runs the agent and demo service in it)"
  value       = module.control_plane.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnets with a NAT gateway"
  value       = module.control_plane.private_subnet_ids
}
