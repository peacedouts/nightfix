# --- API and ingest: HTTPS terminated at an ALB ---------------------------

resource "aws_lb" "public" {
  name                       = "${local.name}-public"
  load_balancer_type         = "application"
  subnets                    = aws_subnet.public[*].id
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
  vpc_id      = aws_vpc.main.id
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
  vpc_id      = aws_vpc.main.id
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
  certificate_arn   = aws_acm_certificate_validation.public.certificate_arn
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
  subnets                          = aws_subnet.public[*].id
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.deletion_protection
}

resource "aws_lb_target_group" "agent" {
  name        = "${local.name}-agent"
  port        = 8443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id
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

# --- Certificates and DNS (Cloudflare) ---------------------------------------

data "cloudflare_zone" "main" {
  name = var.domain
}

resource "aws_acm_certificate" "public" {
  domain_name               = local.api_host
  subject_alternative_names = [local.ingest_host]
  validation_method         = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_record" "acm_validation" {
  for_each = {
    for o in aws_acm_certificate.public.domain_validation_options : o.domain_name => o
  }
  zone_id = data.cloudflare_zone.main.id
  name    = trimsuffix(each.value.resource_record_name, ".")
  type    = each.value.resource_record_type
  content = trimsuffix(each.value.resource_record_value, ".")
  ttl     = 60
  proxied = false
}

resource "aws_acm_certificate_validation" "public" {
  certificate_arn         = aws_acm_certificate.public.arn
  validation_record_fqdns = [for r in cloudflare_record.acm_validation : r.hostname]
}

# DNS only (grey cloud): Cloudflare's proxy would terminate TLS, which breaks
# the agents' mutual TLS and SNS's view of our certificate.
resource "cloudflare_record" "api" {
  zone_id = data.cloudflare_zone.main.id
  name    = var.api_hostname
  type    = "CNAME"
  content = aws_lb.public.dns_name
  ttl     = 300
  proxied = false
}

resource "cloudflare_record" "ingest" {
  zone_id = data.cloudflare_zone.main.id
  name    = var.ingest_hostname
  type    = "CNAME"
  content = aws_lb.public.dns_name
  ttl     = 300
  proxied = false
}

resource "cloudflare_record" "agent" {
  zone_id = data.cloudflare_zone.main.id
  name    = var.agent_hostname
  type    = "CNAME"
  content = aws_lb.agent.dns_name
  ttl     = 300
  proxied = false
}
