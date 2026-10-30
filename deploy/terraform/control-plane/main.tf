# Nightfix's own deployment of the control plane: the shared module, with DNS
# in Cloudflare and rollouts from this repository's GitHub workflows. A client
# deployment uses the same module (see ../examples/self-hosted).

module "control_plane" {
  source = "../modules/nightfix-control-plane"

  environment             = var.environment
  domain                  = var.domain
  api_hostname            = var.api_hostname
  ingest_hostname         = var.ingest_hostname
  agent_hostname          = var.agent_hostname
  image_tag               = var.image_tag
  vpc_cidr                = var.vpc_cidr
  single_nat_gateway      = var.single_nat_gateway
  db_instance_class       = var.db_instance_class
  db_multi_az             = var.db_multi_az
  db_allocated_storage    = var.db_allocated_storage
  db_performance_insights = var.db_performance_insights
  desired_count           = var.desired_count
  task_cpu                = var.task_cpu
  task_memory             = var.task_memory
  auth0_domain            = var.auth0_domain
  auth0_audience          = var.auth0_audience
  auth0_client_ids        = var.auth0_client_ids
  alarm_email             = var.alarm_email
  deletion_protection     = var.deletion_protection
}

# --- DNS (Cloudflare) --------------------------------------------------------
# DNS only (grey cloud): Cloudflare's proxy would terminate TLS, which breaks
# the agents' mutual TLS and SNS's view of our certificate.

data "cloudflare_zone" "main" {
  name = var.domain
}

resource "cloudflare_record" "acm_validation" {
  for_each = module.control_plane.acm_validation_records
  zone_id  = data.cloudflare_zone.main.id
  name     = each.value.name
  type     = each.value.type
  content  = each.value.value
  ttl      = 60
  proxied  = false
}

resource "cloudflare_record" "hosts" {
  for_each = module.control_plane.dns_records
  zone_id  = data.cloudflare_zone.main.id
  name     = trimsuffix(each.key, ".${var.domain}")
  type     = "CNAME"
  content  = each.value
  ttl      = 300
  proxied  = false
}
