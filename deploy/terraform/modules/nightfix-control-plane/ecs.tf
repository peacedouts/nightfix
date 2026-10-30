locals {
  api_host    = "${var.api_hostname}.${var.domain}"
  ingest_host = "${var.ingest_hostname}.${var.domain}"
  agent_host  = "${var.agent_hostname}.${var.domain}"
  image       = var.image != "" ? var.image : "${aws_ecr_repository.controlplane.repository_url}:${var.image_tag}"
  region      = data.aws_region.current.name

  common_env = [
    { name = "AWS_REGION", value = local.region },
    { name = "NIGHTFIX_DB_HOST", value = local.db_host },
    { name = "NIGHTFIX_DB_PORT", value = tostring(local.db_port) },
    { name = "NIGHTFIX_DB_NAME", value = local.db_name },
    { name = "NIGHTFIX_KMS_KEY_ID", value = local.sealing_key_ref },
  ]
  oidc_env = var.oidc == null ? [] : [
    { name = "NIGHTFIX_OIDC_ISSUER", value = var.oidc.issuer },
    { name = "NIGHTFIX_OIDC_AUDIENCE", value = var.oidc.audience },
    { name = "NIGHTFIX_OIDC_ORG", value = var.oidc.org_id },
    { name = "NIGHTFIX_OIDC_CLIENT_IDS", value = join(",", var.oidc.client_ids) },
    { name = "NIGHTFIX_OIDC_ALLOWED_GROUPS", value = join(",", var.oidc.allowed_groups) },
    { name = "NIGHTFIX_OIDC_EMAIL_DOMAINS", value = join(",", var.oidc.email_domains) },
    { name = "NIGHTFIX_OIDC_REQUIRED_CLAIMS", value = join(",", [for k, v in var.oidc.required_claims : "${k}=${v}"]) },
    { name = "NIGHTFIX_OIDC_EMAIL_CLAIM", value = var.oidc.email_claim },
    { name = "NIGHTFIX_OIDC_GROUPS_CLAIM", value = var.oidc.groups_claim },
    { name = "NIGHTFIX_OIDC_EMAIL_VERIFIED_CLAIM", value = var.oidc.email_verified_claim },
    { name = "NIGHTFIX_OIDC_TRUST_EMAIL", value = tostring(var.oidc.trust_email) },
  ]
  app_password_secret = { name = "NIGHTFIX_APP_DB_PASSWORD", valueFrom = aws_secretsmanager_secret.app_db.arn }
  log_config = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.controlplane.name
      "awslogs-region"        = local.region
      "awslogs-stream-prefix" = "controlplane"
    }
  }
}

resource "aws_ecs_cluster" "main" {
  count = local.create_cluster ? 1 : 0
  name  = local.name
  setting {
    name  = "containerInsights"
    value = var.container_insights ? "enabled" : "disabled"
  }
}

resource "aws_cloudwatch_log_group" "controlplane" {
  name              = "/${var.name_prefix}/${var.environment}/controlplane"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.logs_kms_key_arn
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
    # On SIGTERM, serve drains its listeners (up to 10s) and lets claimed
    # notifications finish and be recorded (up to 20s); ECS's default 30s
    # would kill it mid-way and a page could go out twice.
    stopTimeout = 45
    portMappings = [
      { containerPort = 8080, protocol = "tcp" },
      { containerPort = 8081, protocol = "tcp" },
      { containerPort = 8443, protocol = "tcp" },
    ]
    environment = concat(local.common_env, local.oidc_env, [
      { name = "NIGHTFIX_PUBLIC_API_URL", value = "https://${local.api_host}" },
      { name = "NIGHTFIX_PUBLIC_INGEST_URL", value = "https://${local.ingest_host}" },
      { name = "NIGHTFIX_AGENT_TLS_HOSTS", value = local.agent_host },
      { name = "NIGHTFIX_AUTH0_DOMAIN", value = var.auth0_domain },
      { name = "NIGHTFIX_AUTH0_CLIENT_IDS", value = join(",", var.auth0_client_ids) },
      { name = "NIGHTFIX_AUTH0_AUDIENCE", value = var.auth0_audience != "" ? var.auth0_audience : "https://${local.api_host}" },
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
      { name = "NIGHTFIX_DB_HOST", value = local.db_host },
      { name = "NIGHTFIX_DB_PORT", value = tostring(local.db_port) },
      { name = "NIGHTFIX_DB_NAME", value = local.db_name },
      { name = "NIGHTFIX_DB_ADMIN_USER", value = local.db_admin_user },
    ]
    secrets = [
      local.app_password_secret,
      { name = "NIGHTFIX_DB_ADMIN_PASSWORD", valueFrom = "${local.db_admin_secret_arn}:password::" },
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
  cluster                = local.cluster_arn
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
    subnets          = local.private_subnet_ids
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
  # The target groups attach to the ALB through the listener rules; ECS
  # refuses a service whose target group has no load balancer yet.
  depends_on = [aws_lb_listener_rule.api, aws_lb_listener_rule.ingest, aws_lb_listener.agent]
}
