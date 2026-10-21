output "role_arn" {
  description = "Register this in Nightfix as an IAM enrollment rule (POST /v1/enrollment-rules)."
  value       = aws_iam_role.agent.arn
}

output "security_group_id" {
  description = "Allow this group in your databases' security groups if shell steps need them."
  value       = aws_security_group.agent.id
}

output "service_name" {
  value = aws_ecs_service.agent.name
}
