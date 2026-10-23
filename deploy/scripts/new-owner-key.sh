#!/usr/bin/env bash
# Issue a new owner API key for an org: the recovery path when its owner key
# is lost or has leaked. With --revoke-others, every other key of the org is
# revoked in the same transaction (use that for a leak). The key is written
# straight into Secrets Manager by the admin task and shown to you once.
#
#   deploy/scripts/new-owner-key.sh org_… [--revoke-others]
#
# Customers who still hold an owner key can rotate on their own instead:
# POST /v1/api-keys, then POST /v1/api-keys/{id}/revoke on the old one.
#
# Run from deploy/terraform/control-plane's state (reads `terraform output`),
# with AWS credentials that can run the admin task and read the secret.
set -euo pipefail
org="${1:?usage: new-owner-key.sh <org id org_…> [--revoke-others]}"
revoke=false
if [ "${2:-}" = "--revoke-others" ]; then revoke=true; fi
cd "$(dirname "$0")/../terraform/control-plane"
out=$(terraform output -json admin_task)
get() { jq -r ".$1" <<<"$out"; }
export AWS_REGION="$(get region)"

cmd=$(jq -cn --arg o "$org" --argjson r "$revoke" '["org", "new-owner-key", "--org", $o] + (if $r then ["--revoke-others"] else [] end)')
overrides=$(jq -n --argjson c "$cmd" '{containerOverrides: [{name: "admin", command: $c}]}')
task=$(aws ecs run-task --cluster "$(get cluster)" --launch-type FARGATE --task-definition "$(get task_definition)" \
  --network-configuration "awsvpcConfiguration={subnets=[$(get subnets)],securityGroups=[$(get security_group)],assignPublicIp=DISABLED}" \
  --overrides "$overrides" --query 'tasks[0].taskArn' --output text)
echo "Issuing a new owner key for $org (task ${task##*/})…"
aws ecs wait tasks-stopped --cluster "$(get cluster)" --tasks "$task"
code=$(aws ecs describe-tasks --cluster "$(get cluster)" --tasks "$task" --query 'tasks[0].containers[0].exitCode' --output text)
if [ "$code" != "0" ]; then
  echo "Failed (exit $code). See CloudWatch logs, stream prefix controlplane/admin." >&2
  exit 1
fi

# The task names the secret <prefix><org>-<unix time>; take the newest.
secret=$(aws secretsmanager list-secrets --filters "Key=name,Values=$(get cluster)/org-api-keys/$org-" \
  --query 'reverse(sort_by(SecretList, &CreatedDate))[0].Name' --output text)
echo "New owner API key for $org (shown once; store it in your password manager):"
aws secretsmanager get-secret-value --secret-id "$secret" --query SecretString --output text
read -r -p "Delete the secret now that you've saved the key? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  aws secretsmanager delete-secret --secret-id "$secret" --force-delete-without-recovery > /dev/null
  echo "Deleted."
fi
