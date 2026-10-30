# Optional pieces a client account may want: an existing cluster, VPC
# endpoints, WAF, and log export.

locals {
  create_cluster = var.existing_ecs_cluster_arn == ""
  cluster_arn    = local.create_cluster ? aws_ecs_cluster.main[0].arn : var.existing_ecs_cluster_arn
  cluster_name   = local.create_cluster ? aws_ecs_cluster.main[0].name : element(split("/", var.existing_ecs_cluster_arn), 1)
}

# --- VPC endpoints -------------------------------------------------------------

resource "aws_security_group" "endpoints" {
  count       = var.vpc_endpoints ? 1 : 0
  name        = "${local.name}-endpoints"
  description = "AWS service endpoints for the control-plane tasks"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_tasks" {
  count                        = var.vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  referenced_security_group_id = aws_security_group.tasks.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = var.vpc_endpoints ? toset(["kms", "sts", "secretsmanager", "ecr.api", "ecr.dkr", "logs"]) : toset([])
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = { Name = "${local.name}-${each.key}" }
}

# ECR image layers come from S3.
resource "aws_vpc_endpoint" "s3" {
  count             = var.vpc_endpoints ? 1 : 0
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
  tags              = { Name = "${local.name}-s3" }
}

# --- WAF -------------------------------------------------------------------------

resource "aws_wafv2_web_acl_association" "public" {
  count        = var.waf_web_acl_arn != "" ? 1 : 0
  resource_arn = aws_lb.public.arn
  web_acl_arn  = var.waf_web_acl_arn
}

# --- Log export ------------------------------------------------------------------

resource "aws_cloudwatch_log_subscription_filter" "controlplane" {
  count           = var.log_subscription != null ? 1 : 0
  name            = "${local.name}-export"
  log_group_name  = aws_cloudwatch_log_group.controlplane.name
  filter_pattern  = var.log_subscription.filter_pattern
  destination_arn = var.log_subscription.destination_arn
  role_arn        = var.log_subscription.role_arn != "" ? var.log_subscription.role_arn : null
}
