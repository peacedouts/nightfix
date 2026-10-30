#!/usr/bin/env bash
# Link a customer's Auth0 Organization to their Nightfix org, so their
# people can sign in. An operator step: do it once the customer has shown
# they control that Auth0 Organization (its id isn't secret, which is why
# the API doesn't let an org's owner do it).
#
#   deploy/scripts/link-auth0.sh org_… org_abc123
#
# Reads `terraform output` from deploy/terraform/control-plane, or from
# NIGHTFIX_TF_DIR (a self-hosted root such as examples/self-hosted),
# with AWS credentials that can run the admin task.
set -euo pipefail
org="${1:?usage: link-auth0.sh <nightfix org id org_…> <auth0 organization id org_…>}"
auth0="${2:?usage: link-auth0.sh <nightfix org id org_…> <auth0 organization id org_…>}"
cd "${NIGHTFIX_TF_DIR:-$(dirname "$0")/../terraform/control-plane}"
out=$(terraform output -json admin_task)
get() { jq -r ".$1" <<<"$out"; }
export AWS_REGION="$(get region)"

overrides=$(jq -n --arg o "$org" --arg a "$auth0" '{containerOverrides: [{name: "admin", command: ["org", "link-auth0", "--org", $o, "--auth0-org", $a]}]}')
task=$(aws ecs run-task --cluster "$(get cluster)" --launch-type FARGATE --task-definition "$(get task_definition)" \
  --network-configuration "awsvpcConfiguration={subnets=[$(get subnets)],securityGroups=[$(get security_group)],assignPublicIp=DISABLED}" \
  --overrides "$overrides" --query 'tasks[0].taskArn' --output text)
echo "Linking $org to Auth0 organization $auth0 (task ${task##*/})…"
aws ecs wait tasks-stopped --cluster "$(get cluster)" --tasks "$task"
code=$(aws ecs describe-tasks --cluster "$(get cluster)" --tasks "$task" --query 'tasks[0].containers[0].exitCode' --output text)
if [ "$code" != "0" ]; then
  echo "Failed (exit $code). See CloudWatch logs, stream prefix controlplane/admin." >&2
  exit 1
fi
echo "Linked."
