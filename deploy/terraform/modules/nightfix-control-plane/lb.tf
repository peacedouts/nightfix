# --- API and ingest: HTTPS terminated at an ALB ---------------------------

resource "aws_lb" "public" {
  name                       = "${local.name}-public"
  load_balancer_type         = "application"
  subnets                    = local.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 60
}

resource "aws_lb_target_group" "api" {
  name        = "${local.name}-api"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.vpc_id
  health_check {
    path    = "/healthz"
    matcher = "200"
  }
  deregistration_delay = 30
}

resource "aws_lb_target_group" "ingest" {
  name        = "${local.name}-ingest"
  port        = 8081
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.vpc_id
  health_check {
    path    = "/healthz"
    matcher = "200"
  }
  deregistration_delay = 30
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.public.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
  condition {
    host_header {
      values = [local.api_host]
    }
  }
}

resource "aws_lb_listener_rule" "ingest" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingest.arn
  }
  condition {
    host_header {
      values = [local.ingest_host]
    }
  }
}

# --- Agent gateway: TCP straight through, so the tasks do mutual TLS ---------

resource "aws_lb" "agent" {
  name                             = "${local.name}-agent"
  load_balancer_type               = "network"
  subnets                          = local.public_subnet_ids
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.deletion_protection
}

resource "aws_lb_target_group" "agent" {
  name        = "${local.name}-agent"
  port        = 8443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = local.vpc_id
  health_check {
    protocol = "TCP"
  }
  deregistration_delay = 60
}

resource "aws_lb_listener" "agent" {
  load_balancer_arn = aws_lb.agent.arn
  port              = 443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.agent.arn
  }
}

# --- Certificates and DNS ----------------------------------------------------
#
# With route53_zone_id, everything is created here. Otherwise the
# acm_validation_records and dns_records outputs say what to create in your
# DNS; apply waits at the certificate validation until the validation
# records resolve. All records are DNS only: a proxy (Cloudflare's orange
# cloud) would terminate TLS, which breaks the agents' mutual TLS and SNS's
# view of the certificate.

locals {
  use_route53 = var.route53_zone_id != ""
  # Not try(): it turns a partly unknown value (a new certificate's records)
  # wholly unknown, and for_each over it then fails at plan. The domain names
  # (the keys) are known at plan; only the record values aren't.
  acm_validation = local.create_certificate ? {
    for o in aws_acm_certificate.public[0].domain_validation_options : o.domain_name => {
      name  = trimsuffix(o.resource_record_name, ".")
      type  = o.resource_record_type
      value = trimsuffix(o.resource_record_value, ".")
    }
  } : {}
  host_records = {
    (local.api_host)    = aws_lb.public.dns_name
    (local.ingest_host) = aws_lb.public.dns_name
    (local.agent_host)  = aws_lb.agent.dns_name
  }
}

resource "aws_acm_certificate" "public" {
  count                     = local.create_certificate ? 1 : 0
  domain_name               = local.api_host
  subject_alternative_names = [local.ingest_host]
  validation_method         = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "acm_validation" {
  for_each        = local.use_route53 ? local.acm_validation : {}
  zone_id         = var.route53_zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.value]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "public" {
  count                   = local.create_certificate ? 1 : 0
  certificate_arn         = aws_acm_certificate.public[0].arn
  validation_record_fqdns = local.use_route53 ? [for r in aws_route53_record.acm_validation : r.fqdn] : null
}

resource "aws_route53_record" "hosts" {
  for_each = local.use_route53 ? local.host_records : {}
  zone_id  = var.route53_zone_id
  name     = each.key
  type     = "CNAME"
  records  = [each.value]
  ttl      = 300
}
