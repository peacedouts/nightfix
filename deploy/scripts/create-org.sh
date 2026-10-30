#!/usr/bin/env bash
# Create a Nightfix org on the deployed control plane. The owner API key is
# written straight into Secrets Manager by the task and never printed or
# logged; this script then shows it to you once.
#
#   deploy/scripts/create-org.sh "Acme Inc" acme
#
# Reads `terraform output` from deploy/terraform/control-plane, or from
# NIGHTFIX_TF_DIR (a self-hosted root such as examples/self-hosted),
# with AWS credentials that can run the admin task and read the secret.
set -euo pipefail
name="${1:?usage: create-org.sh <name> <slug>}"
slug="${2:?usage: create-org.sh <name> <slug>}"
cd "${NIGHTFIX_TF_DIR:-$(dirname "$0")/../terraform/control-plane}"
out=$(terraform output -json admin_task)
get() { jq -r ".$1" <<<"$out"; }
export AWS_REGION="$(get region)"

overrides=$(jq -n --arg n "$name" --arg s "$slug" '{containerOverrides: [{name: "admin", command: ["org", "create", "--name", $n, "--slug", $s]}]}')
task=$(aws ecs run-task --cluster "$(get cluster)" --launch-type FARGATE --task-definition "$(get task_definition)" \
  --network-configuration "awsvpcConfiguration={subnets=[$(get subnets)],securityGroups=[$(get security_group)],assignPublicIp=DISABLED}" \
  --overrides "$overrides" --query 'tasks[0].taskArn' --output text)
echo "Creating org $slug (task ${task##*/})…"
aws ecs wait tasks-stopped --cluster "$(get cluster)" --tasks "$task"
code=$(aws ecs describe-tasks --cluster "$(get cluster)" --tasks "$task" --query 'tasks[0].containers[0].exitCode' --output text)
if [ "$code" != "0" ]; then
  echo "Failed (exit $code). See CloudWatch logs, stream prefix controlplane/admin." >&2
  exit 1
fi

secret="$(get org_secret_prefix)$slug"
echo "Owner API key for $slug (shown once; store it in your password manager):"
aws secretsmanager get-secret-value --secret-id "$secret" --query SecretString --output text
read -r -p "Delete the secret now that you've saved the key? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  aws secretsmanager delete-secret --secret-id "$secret" --force-delete-without-recovery > /dev/null
  echo "Deleted."
fi
