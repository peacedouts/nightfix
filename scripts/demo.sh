#!/usr/bin/env bash
# Walking-skeleton demo: a CloudWatch alarm auto-fixes itself and nobody is paged.
#
#   scripts/demo.sh              # happy path: auto-remediated, no page
#   DEMO_SCENARIO=fail scripts/demo.sh   # the fix doesn't work: on-call is paged
#
# Runs everything locally: Postgres, the control plane, an agent, and devstub
# (simulated ECS, SNS, Slack and PagerDuty). Needs Go, PostgreSQL server
# binaries, curl and python3.
set -euo pipefail
cd "$(dirname "$0")/.."

SCENARIO="${DEMO_SCENARIO:-heal}"
STUB=http://127.0.0.1:9100
API=http://127.0.0.1:18080
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

say()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }
api()  { curl -fsS -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' "$@"; }

say "Building"
mkdir -p bin
GOFLAGS="${GOFLAGS:-}" go build -o bin/ ./cmd/...

say "Starting Postgres and migrating a fresh database"
ADMIN="$(scripts/dev-postgres.sh start)"
psql "$ADMIN" -qc "DROP DATABASE IF EXISTS lightning_demo WITH (FORCE)" -c "CREATE DATABASE lightning_demo" >/dev/null
DEMO_ADMIN="${ADMIN/\/postgres\?/\/lightning_demo?}"
LIR_ADMIN_DATABASE_URL="$DEMO_ADMIN" LIR_APP_DB_PASSWORD=demo bin/lightning migrate
export LIR_DATABASE_URL="${DEMO_ADMIN/postgres@/lir_app:demo@}"
export LIR_STATE_DIR="$WORK/state"
export LIR_API_ADDR=127.0.0.1:18080 LIR_INGEST_ADDR=127.0.0.1:18081 LIR_AGENT_ADDR=127.0.0.1:18443
export LIR_PUBLIC_INGEST_URL=http://127.0.0.1:18081
export LIR_SNS_DEV_CERT_PREFIX="$STUB/sns/"   # trust devstub's SNS signing cert (local only)
export LIR_STS_DEV_ENDPOINT="$STUB/sts/"       # devstub plays STS for IAM enrollment (local only)

say "Starting devstub (simulated ECS, SNS, Slack, PagerDuty)"
bin/devstub --heal-after 4s > "$WORK/devstub.log" 2>&1 & PIDS+=($!)

say "Creating org"
ORG_OUT="$(bin/lightning org create --name "Acme" --slug acme)"
echo "$ORG_OUT"
KEY="$(echo "$ORG_OUT" | awk '/api key/ {print $3}')"
ORG="$(echo "$ORG_OUT" | awk '/^org:/ {print $2}')"

say "Starting the control plane"
bin/lightning serve > "$WORK/controlplane.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do curl -fsS "$API/healthz" >/dev/null 2>&1 && break; sleep 0.2; done

say "Configuring: service, Slack + PagerDuty targets, CloudWatch integration"
api -X POST "$API/v1/services" -d '{"name":"checkout-api","max_hold":"2m","verification_window":"30s"}' >/dev/null
api -X POST "$API/v1/services/checkout-api/escalation-targets" -d "{\"type\":\"slack\",\"url\":\"$STUB/slack\"}" >/dev/null
api -X POST "$API/v1/services/checkout-api/escalation-targets" \
  -d "{\"type\":\"pagerduty\",\"routing_key\":\"demo-routing-key\",\"events_url\":\"$STUB/pagerduty\"}" >/dev/null
TOPIC=arn:aws:sns:us-east-1:123456789012:lightning-alarms
INGEST="$(api -X POST "$API/v1/integrations" \
  -d "{\"type\":\"cloudwatch\",\"name\":\"prod alarms\",\"default_service\":\"checkout-api\",\"topic_arn\":\"$TOPIC\"}" | json 'd["ingest_url"]')"
echo "ingest URL: $INGEST"

say "Publishing the ecs-service-restart runbook (validated, canonicalized, signed)"
RB=examples/runbooks/ecs-service-restart.yaml
if [ "$SCENARIO" = fail ]; then
  sed 's/^      timeout: 2m$/      timeout: 10s/' "$RB" > "$WORK/runbook.yaml"; RB="$WORK/runbook.yaml"
fi
api -X PUT "$API/v1/runbooks/ecs-service-restart" --data-binary @"$RB" | json '"version %s  %s  signed by %s" % (d["version"], d["digest"][:23]+"…", ", ".join(d["signed_by"]))'

say "Enrolling an agent by its IAM role (signed STS GetCallerIdentity → 24h mTLS cert; labels come from the rule)"
api -X POST "$API/v1/enrollment-rules" \
  -d '{"method":"iam","role_arn":"arn:aws:iam::123456789012:role/lightning-agent","labels":{"env":"prod"},"max_agents":1}' \
  | json '"rule: role %s in account %s → labels env=prod" % (d["role_name"], d["aws_account_id"])'
LIR_AWS_ENDPOINT_URL="$STUB/aws" LIR_STS_ENDPOINT_URL="$STUB/sts/" \
AWS_ACCESS_KEY_ID=AKIDEXAMPLE AWS_SECRET_ACCESS_KEY=example-secret AWS_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true \
  bin/lightning-agent --endpoint https://127.0.0.1:18443 --ca-file "$LIR_STATE_DIR/ca.crt" \
    --org "$ORG" --state-dir "$WORK/agent" > "$WORK/agent.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do
  [ "$(api "$API/v1/agents" | json 'd[0]["status"] if d else ""' 2>/dev/null)" = online ] && break; sleep 0.3
done
api "$API/v1/agents" | json '"agent %s online, labels %s" % (d[0]["id"], d[0]["labels"])'

[ "$SCENARIO" = fail ] && curl -fsS -X POST "$STUB/ecs/heals?value=false" >/dev/null
curl -fsS -X POST "$STUB/ecs/services" -d '{"cluster":"prod-east","service":"checkout-api"}' >/dev/null

say "02:14 — CloudWatch alarm fires (delivered as a signed SNS notification)"
curl -fsS -X POST "$STUB/sns/publish" -d "{\"ingest_url\":\"$INGEST\",\"topic_arn\":\"$TOPIC\",\"alarm\":\"ecs-unhealthy-checkout\",\"state\":\"ALARM\",\"cluster\":\"prod-east\",\"service\":\"checkout-api\"}" >/dev/null

state() { api "$API/v1/incidents/1" 2>/dev/null | json 'd["status"]' 2>/dev/null || true; }
run_status() { local r; r="$(api "$API/v1/incidents/1" | json 'd.get("remediation_run","")')"; [ -n "$r" ] && api "$API/v1/runs/$r" | json 'd["status"]'; }

for _ in $(seq 60); do [ "$(run_status 2>/dev/null)" != running ] && [ -n "$(run_status 2>/dev/null)" ] && break; sleep 0.5; done
echo "remediation run: $(run_status)"

if [ "$(run_status)" = succeeded ]; then
  say "The service is healthy again — CloudWatch reports OK"
  curl -fsS -X POST "$STUB/sns/publish" -d "{\"ingest_url\":\"$INGEST\",\"topic_arn\":\"$TOPIC\",\"alarm\":\"ecs-unhealthy-checkout\",\"state\":\"OK\",\"cluster\":\"prod-east\",\"service\":\"checkout-api\"}" >/dev/null
  for _ in $(seq 30); do [ "$(state)" = resolved ] && break; sleep 0.3; done
else
  for _ in $(seq 30); do [ "$(state)" = triggered ] && break; sleep 0.3; done
fi
sleep 1

say "Incident #1"
api "$API/v1/incidents/1" | json '"status: %s   resolution: %s   paged: %s" % (d["status"], d["resolution"] or "-", d["paged"])'
say "Timeline"
api "$API/v1/incidents/1/timeline" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    print("  %s  %-22s %s" % (e["at"][11:19], e["type"], e["message"].strip().splitlines()[0]))'
say "What Slack and PagerDuty received"
curl -fsS "$STUB/state" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for m in d["slack"] or []: print("  slack:     " + m.splitlines()[0])
print("  pagerduty: " + (", ".join("%s %s" % (p["event_action"], p["dedup_key"]) for p in d["pagerduty"] or []) or "nothing — nobody was woken up"))
print("  aws calls: " + ", ".join(d["aws_calls"] or []))'
echo
echo "Logs: $WORK"
