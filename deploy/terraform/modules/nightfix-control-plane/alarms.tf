# Nightfix pages its customers, so it has to know first when it's sick.
resource "aws_sns_topic" "alarms" {
  count = local.create_alarm_topic ? 1 : 0
  name  = "${local.name}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = local.alarm_topic_arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alarm_actions    = [local.alarm_topic_arn]
  metric_namespace = "Nightfix/${local.name}"
}

# Needs Container Insights (on the module's cluster, or yours): without it the
# metric is missing, which this alarm treats as breaching.
resource "aws_cloudwatch_metric_alarm" "running_tasks" {
  count               = var.container_insights ? 1 : 0
  alarm_name          = "${local.name}-running-tasks-low"
  alarm_description   = "Fewer control-plane tasks running than desired"
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  dimensions          = { ClusterName = local.cluster_name, ServiceName = aws_ecs_service.controlplane.name }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = var.desired_count
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${local.name}-api-5xx"
  alarm_description   = "The API or ingest is returning server errors"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = { LoadBalancer = aws_lb.public.arn_suffix }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_ingest" {
  alarm_name          = "${local.name}-ingest-unhealthy"
  alarm_description   = "Alert ingest has unhealthy targets: customer alerts may be dropped"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = { LoadBalancer = aws_lb.public.arn_suffix, TargetGroup = aws_lb_target_group.ingest.arn_suffix }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  count               = local.db_alarm_identifier != "" ? 1 : 0
  alarm_name          = "${local.name}-db-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = local.db_alarm_identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  count               = local.db_alarm_identifier != "" ? 1 : 0
  alarm_name          = "${local.name}-db-free-storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = local.db_alarm_identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 2 * 1024 * 1024 * 1024
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# Work that silently isn't getting done doesn't show up as 5xx or missing
# tasks: an alert event that couldn't be processed, a page that keeps
# failing, a worker loop or partition maintenance erroring. All of those log
# at level=ERROR, so any such line alarms. The page-specific one says what
# to check first.
resource "aws_cloudwatch_log_metric_filter" "errors" {
  name           = "${local.name}-errors"
  log_group_name = aws_cloudwatch_log_group.controlplane.name
  pattern        = "\"level=ERROR\""
  metric_transformation {
    namespace     = local.metric_namespace
    name          = "ErrorLogLines"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${local.name}-error-logs"
  alarm_description   = "The control plane logged an error (CloudWatch Logs: filter level=ERROR). Failed alert events: GET /v1/alert-events/failed."
  namespace           = local.metric_namespace
  metric_name         = "ErrorLogLines"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_log_metric_filter" "pages_failing" {
  name           = "${local.name}-pages-failing"
  log_group_name = aws_cloudwatch_log_group.controlplane.name
  pattern        = "?\"page delivery failing\" ?\"notification abandoned\""
  metric_transformation {
    namespace     = local.metric_namespace
    name          = "PagesFailing"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "pages_failing" {
  alarm_name          = "${local.name}-pages-failing"
  alarm_description   = "A customer's page or resolve keeps failing or was abandoned (its incident timeline says why: often a revoked PagerDuty routing key or Slack webhook)."
  namespace           = local.metric_namespace
  metric_name         = "PagesFailing"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}
