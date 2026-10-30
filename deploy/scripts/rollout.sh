#!/usr/bin/env bash
# Roll out a released control-plane image to a self-hosted deployment, with
# the image and commit from the release notes:
#
#   deploy/scripts/rollout.sh ghcr.io/peacedouts/nightfix-controlplane@sha256:<digest> <commit>
#
#   1. verify the image's Sigstore signature names this project's images.yml
#      on main at that commit (so an older or unreleased build signed on main
#      can't be passed off as the release), unless NIGHTFIX_SKIP_VERIFY=1, for
#      an image you built yourself
#   2. copy it, unchanged and by digest, into the deployment's own ECR
#      repository, so task replacements never depend on GHCR being up
#   3. register new revisions of the migrate, service and admin task
#      definitions, pinned to that digest
#   4. run migrations and stop on failure
#   5. update the service and wait until it's stable (the ECS deployment
#      circuit breaker rolls back automatically if new tasks don't get healthy)
#
# The same steps as .github/workflows/deploy.yml, for an account this
# repository's workflows don't deploy to. Reads `terraform output rollout`
# from NIGHTFIX_TF_DIR (default deploy/terraform/control-plane). Needs the aws
# CLI, jq, cosign, and crane or skopeo.
set -euo pipefail

usage="usage: rollout.sh <image>@sha256:<digest> <release commit>"
src="${1:?$usage}"
commit="${2:-}"
if ! [[ "$src" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "The image must be pinned by digest: <registry>/<repository>@sha256:<64 hex digits>" >&2
  exit 1
fi
digest="${src#*@}"
release_repo="${NIGHTFIX_RELEASE_REPO:-peacedouts/nightfix}"
if [ "$release_repo" != "peacedouts/nightfix" ]; then
  echo "Note: trusting releases signed by $release_repo (NIGHTFIX_RELEASE_REPO), not peacedouts/nightfix." >&2
fi

cd "${NIGHTFIX_TF_DIR:-$(dirname "$0")/../terraform/control-plane}"
out=$(terraform output -json rollout)
get() { jq -r ".$1" <<<"$out"; }
export AWS_REGION="$(get region)"
cluster="$(get cluster)"
repo="$(get ecr_repository)"
registry="${repo%%/*}"

# 1. Verify.
if [ "${NIGHTFIX_SKIP_VERIFY:-}" = "1" ]; then
  echo "Skipping signature verification (NIGHTFIX_SKIP_VERIFY=1)." >&2
else
  if ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Give the release commit (the full SHA from the release notes) after the image. $usage" >&2
    exit 1
  fi
  # The agent image has the same signer: make sure this is the control plane.
  case "${src%@*}" in
    */nightfix-controlplane) ;;
    *) echo "$src isn't a nightfix-controlplane image." >&2; exit 1 ;;
  esac
  cosign verify "$src" \
    --certificate-identity "https://github.com/$release_repo/.github/workflows/images.yml@refs/heads/main" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository "$release_repo" \
    --certificate-github-workflow-sha "$commit" > /dev/null
  echo "Verified $src (signed by $release_repo images.yml on main at $commit)"
fi

# 2. Copy into ECR, preserving the digest. ECR tags are immutable, so the tag
# names the digest; an existing tag means it was copied before.
tag="release-${digest#sha256:}"
tag="${tag:0:40}"
existing=$(aws ecr describe-images --repository-name "${repo#*/}" --image-ids imageTag="$tag" \
  --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)
if [ -z "$existing" ] || [ "$existing" = "None" ]; then
  password=$(aws ecr get-login-password)
  if command -v crane > /dev/null; then
    crane auth login "$registry" -u AWS --password-stdin <<<"$password" > /dev/null
    crane copy "$src" "$repo:$tag"
  elif command -v skopeo > /dev/null; then
    skopeo copy --all --preserve-digests --dest-creds "AWS:$password" "docker://$src" "docker://$repo:$tag"
  else
    echo "Install crane or skopeo to copy the image (they keep its digest)." >&2
    exit 1
  fi
  existing=$(aws ecr describe-images --repository-name "${repo#*/}" --image-ids imageTag="$tag" \
    --query 'imageDetails[0].imageDigest' --output text)
fi
if [ "$existing" != "$digest" ]; then
  echo "$repo:$tag has digest $existing, not $digest; refusing to deploy it." >&2
  exit 1
fi
image="$repo@$digest"
echo "Deploying $image"

# 3. Register task definitions.
register() {
  aws ecs describe-task-definition --task-definition "$1" --query taskDefinition \
    | jq --arg img "$image" '.containerDefinitions[0].image = $img
        | del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)' \
    > "$tmp/td.json"
  aws ecs register-task-definition --cli-input-json "file://$tmp/td.json" --query taskDefinition.taskDefinitionArn --output text
}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
migrate_td=$(register "$(get migrate_family)")
service_td=$(register "$(get service_family)")
register "$(get admin_family)" > /dev/null

# 4. Migrate.
net="awsvpcConfiguration={subnets=[$(get private_subnets)],securityGroups=[$(get security_group)],assignPublicIp=DISABLED}"
task=$(aws ecs run-task --cluster "$cluster" --launch-type FARGATE --task-definition "$migrate_td" \
  --network-configuration "$net" --query 'tasks[0].taskArn' --output text)
echo "Running migrations (task ${task##*/})…"
aws ecs wait tasks-stopped --cluster "$cluster" --tasks "$task"
code=$(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" --query 'tasks[0].containers[0].exitCode' --output text)
if [ "$code" != "0" ]; then
  echo "Migrations failed (exit $code); see the controlplane/migrate logs in CloudWatch. Nothing was rolled out." >&2
  exit 1
fi

# 5. Roll out. services-stable also succeeds after the circuit breaker has
# rolled back, so check the new revision is what's running.
service="$(get service)"
aws ecs update-service --cluster "$cluster" --service "$service" --task-definition "$service_td" > /dev/null
echo "Rolling out…"
aws ecs wait services-stable --cluster "$cluster" --services "$service"
read -r td state < <(aws ecs describe-services --cluster "$cluster" --services "$service" \
  --query 'services[0].deployments[?status==`PRIMARY`]|[0].[taskDefinition,rolloutState]' --output text)
if [ "$td" != "$service_td" ] || [ "$state" != "COMPLETED" ]; then
  echo "The rollout didn't complete (running: $td, $state); ECS rolled back. Migrations had already run; see the service events and task logs." >&2
  exit 1
fi
echo "Deployed $image"
