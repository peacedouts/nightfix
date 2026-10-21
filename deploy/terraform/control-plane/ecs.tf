locals {
  api_host    = "${var.api_hostname}.${var.domain}"
  ingest_host = "${var.ingest_hostname}.${var.domain}"
  agent_host  = "${var.agent_hostname}.${var.domain}"
  image       = "${aws_ecr_repository.controlplane.repository_url}:${var.image_tag}"

  common_env = [
    { name = "AWS_REGION", value = var.region },
    { name = "NIGHTFIX_DB_HOST", value = aws_db_instance.main.address },
    { name = "NIGHTFIX_DB_NAME", value = aws_db_instance.main.db_name },
    { name = "NIGHTFIX_KMS_KEY_ID", value = aws_kms_alias.sealing.name },
  ]
  app_password_secret = { name = "NIGHTFIX_APP_DB_PASSWORD", valueFrom = aws_secretsmanager_secret.app_db.arn }
  log_config = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.controlplane.name
      "awslogs-region"        = var.region
      "awslogs-stream-prefix" = "controlplane"
    }
  }
}

resource "aws_ecs_cluster" "main" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "controlplane" {
  name              = "/nightfix/${var.environment}/controlplane"
  retention_in_days = 90
}

resource "aws_ecs_task_definition" "controlplane" {
  family                   = "${local.name}-controlplane"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name                   = "controlplane"
    image                  = local.image
    essential              = true
    command                = ["serve"]
    readonlyRootFilesystem = true
    portMappings = [
      { containerPort = 8080, protocol = "tcp" },
      { containerPort = 8081, protocol = "tcp" },
      { containerPort = 8443, protocol = "tcp" },
    ]
    environment = concat(local.common_env, [
      { name = "NIGHTFIX_PUBLIC_API_URL", value = "https://${local.api_host}" },
      { name = "NIGHTFIX_PUBLIC_INGEST_URL", value = "https://${local.ingest_host}" },
      { name = "NIGHTFIX_AGENT_TLS_HOSTS", value = local.agent_host },
      { name = "NIGHTFIX_AUTH0_DOMAIN", value = var.auth0_domain },
      { name = "NIGHTFIX_AUTH0_AUDIENCE", value = var.auth0_audience },
    ])
    secrets          = [local.app_password_secret]
    logConfiguration = local.log_config
  }])
}

# Run before each rollout by the deploy workflow (and once by hand on first
# setup). Connects as the RDS master user, applies migrations, and sets the
# nfx_app password.
resource "aws_ecs_task_definition" "migrate" {
  family                   = "${local.name}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.migrate_execution.arn # no task role: migrations need no AWS access
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name                   = "migrate"
    image                  = local.image
    essential              = true
    command                = ["migrate"]
    readonlyRootFilesystem = true
    environment = [
      { name = "NIGHTFIX_DB_HOST", value = aws_db_instance.main.address },
      { name = "NIGHTFIX_DB_NAME", value = aws_db_instance.main.db_name },
      { name = "NIGHTFIX_DB_ADMIN_USER", value = aws_db_instance.main.username },
    ]
    secrets = [
      local.app_password_secret,
      { name = "NIGHTFIX_DB_ADMIN_PASSWORD", valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:password::" },
    ]
    logConfiguration = local.log_config
  }])
}

# `nightfix org create`, run on demand with a command override
# (deploy/scripts/create-org.sh). The owner key goes to Secrets Manager.
resource "aws_ecs_task_definition" "admin" {
  family                   = "${local.name}-admin"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.admin.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name                   = "admin"
    image                  = local.image
    essential              = true
    command                = ["org"]
    readonlyRootFilesystem = true
    environment = concat(local.common_env, [
      { name = "NIGHTFIX_ORG_KEY_SECRET_PREFIX", value = "${local.name}/org-api-keys/" },
    ])
    secrets          = [local.app_password_secret]
    logConfiguration = local.log_config
  }])
}

resource "aws_ecs_service" "controlplane" {
  name                   = "controlplane"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.controlplane.arn
  desired_count          = var.desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false
  propagate_tags         = "SERVICE"

  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "controlplane"
    container_port   = 8080
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.ingest.arn
    container_name   = "controlplane"
    container_port   = 8081
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.agent.arn
    container_name   = "controlplane"
    container_port   = 8443
  }

  # The deploy workflow registers new task definition revisions; Terraform
  # owns the infrastructure, not which image is running.
  lifecycle {
    ignore_changes = [task_definition]
  }
  depends_on = [aws_lb_listener.https, aws_lb_listener.agent]
}
