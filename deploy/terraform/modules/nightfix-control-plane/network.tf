data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name       = "${var.name_prefix}-${var.environment}"
  create_vpc = var.existing_vpc == null
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)

  vpc_id             = local.create_vpc ? aws_vpc.main[0].id : var.existing_vpc.vpc_id
  public_subnet_ids  = local.create_vpc ? aws_subnet.public[*].id : var.existing_vpc.public_subnet_ids
  private_subnet_ids = local.create_vpc ? aws_subnet.private[*].id : var.existing_vpc.private_subnet_ids
}

# --- VPC (unless existing_vpc is given) ---------------------------------------

resource "aws_vpc" "main" {
  count                = local.create_vpc ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = local.name }
}

resource "aws_internet_gateway" "main" {
  count  = local.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id
  tags   = { Name = local.name }
}

# Load balancers only.
resource "aws_subnet" "public" {
  count             = local.create_vpc ? length(local.azs) : 0
  vpc_id            = aws_vpc.main[0].id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  tags              = { Name = "${local.name}-public-${local.azs[count.index]}" }
}

# Tasks and the database. No public IPs.
resource "aws_subnet" "private" {
  count             = local.create_vpc ? length(local.azs) : 0
  vpc_id            = aws_vpc.main[0].id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 8)
  tags              = { Name = "${local.name}-private-${local.azs[count.index]}" }
}

resource "aws_route_table" "public" {
  count  = local.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }
  tags = { Name = "${local.name}-public" }
}

resource "aws_route_table_association" "public" {
  count          = local.create_vpc ? length(local.azs) : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# Tasks need outbound HTTPS: STS (IAM enrollment), SNS certificates,
# Slack, PagerDuty, Auth0 and KMS.
resource "aws_eip" "nat" {
  count  = local.create_vpc ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0
  domain = "vpc"
  tags   = { Name = "${local.name}-nat-${count.index}" }
}

resource "aws_nat_gateway" "main" {
  count         = length(aws_eip.nat)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "${local.name}-${count.index}" }
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "private" {
  count  = local.create_vpc ? length(local.azs) : 0
  vpc_id = aws_vpc.main[0].id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[var.single_nat_gateway ? 0 : count.index].id
  }
  tags = { Name = "${local.name}-private-${local.azs[count.index]}" }
}

resource "aws_route_table_association" "private" {
  count          = local.create_vpc ? length(local.azs) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Flow logs: security reviews ask for them, and they're cheap at this size.
# An existing VPC keeps whatever flow logging it already has.
resource "aws_cloudwatch_log_group" "flow" {
  count             = local.create_vpc ? 1 : 0
  name              = "/${var.name_prefix}/${var.environment}/vpc-flow"
  retention_in_days = 30
  kms_key_id        = local.logs_kms_key_arn
}

resource "aws_iam_role" "flow" {
  count                = local.create_vpc ? 1 : 0
  name                 = "${local.name}-vpc-flow"
  path                 = var.iam_role_path
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow" {
  count = local.create_vpc ? 1 : 0
  role  = aws_iam_role.flow[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow[0].arn}:*"
    }]
  })
}

resource "aws_flow_log" "main" {
  count           = local.create_vpc ? 1 : 0
  vpc_id          = aws_vpc.main[0].id
  traffic_type    = "REJECT"
  log_destination = aws_cloudwatch_log_group.flow[0].arn
  iam_role_arn    = aws_iam_role.flow[0].arn
}

# --- Security groups -------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Public HTTPS for the API and alert ingest"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.ingest_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  for_each          = toset(var.ingest_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "Redirected to HTTPS"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.tasks.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8081
}

resource "aws_security_group" "nlb" {
  name        = "${local.name}-nlb"
  description = "Agent gateway: TCP 443 passed through to the tasks for mutual TLS"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "nlb_agents" {
  for_each          = toset(var.agent_ingress_cidrs)
  security_group_id = aws_security_group.nlb.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_tasks" {
  security_group_id            = aws_security_group.nlb.id
  referenced_security_group_id = aws_security_group.tasks.id
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
}

resource "aws_security_group" "tasks" {
  name        = "${local.name}-tasks"
  description = "Control-plane tasks"
  vpc_id      = local.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_alb" {
  security_group_id            = aws_security_group.tasks.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8081
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_nlb" {
  security_group_id            = aws_security_group.tasks.id
  referenced_security_group_id = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
}

resource "aws_vpc_security_group_egress_rule" "tasks_https" {
  security_group_id = aws_security_group.tasks.id
  description       = "STS, KMS, SNS certs, Slack, PagerDuty, Auth0, ECR"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "tasks_to_db" {
  security_group_id            = aws_security_group.tasks.id
  referenced_security_group_id = local.db_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_security_group" "db" {
  count       = local.create_db ? 1 : 0
  name        = "${local.name}-db"
  description = "Postgres, reachable only from control-plane tasks"
  vpc_id      = local.vpc_id
}

# On the module's database, or on an existing one's security group.
resource "aws_vpc_security_group_ingress_rule" "db_from_tasks" {
  security_group_id            = local.db_security_group_id
  description                  = "Nightfix ${local.name} control-plane tasks"
  referenced_security_group_id = aws_security_group.tasks.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}
