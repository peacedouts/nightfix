# Nightfix

By [Zachary Adams](https://github.com/peacedouts)

Opensource incident response for your AWS account. It tries the obvious fix first and only pages you when that fails. Everything runs in your account, including the control plane, its database, and an agent in your VPC that can only do what its IAM role allows.

## Try it locally

Needs Go 1.24+, PostgreSQL 15+ (`initdb`, `pg_ctl`, `psql`), `curl` and `python3`.

```bash
make demo        # the alarm fixes itself; nobody is paged
make demo-fail   # the fix fails; on-call is paged, then the page resolves
```

Each demo spins up a temporary Postgres, the control plane and a real agent, with fake ECS, SNS, Slack and PagerDuty. When it's done, it prints the incident timeline and what Slack and PagerDuty would have seen.

## How it works

```
 CloudWatch ─SNS─┐                                      your pager (PagerDuty)
 webhooks ───────┤   control plane (ECS Fargate + Postgres)     ▲
                 └──▶ ingest → incidents → runs ─────────────────┤
                       ▲            │ signed steps               Slack (approvals, updates)
 your IdP (OIDC) ──────┘            ▼
                            agent (ECS or EKS, outbound mTLS only)
                                    │ your IAM role
                                    ▼
                            your AWS APIs, shell steps
```

- **Alerts** from CloudWatch (through SNS, signature-checked) or signed webhooks are deduplicated and grouped into incidents.
- **Runbooks** are YAML, linted and signed on publish. If a runbook is allowed to run before paging, Nightfix holds the page while it works. If the alert clears, nobody gets woken up. Risky steps wait for approval in Slack.
- **Agents** only connect outbound, over mutual TLS. They sign in with their IAM role instead of a token, refuse any step that isn't in the signed runbook or their allowlist, and strip secrets from their output.
- **Tenancy and audit:** row-level security on every table, credentials sealed with KMS, and a hash-chained audit log.

The full list of what's built, and what isn't yet, is in [docs/capabilities.md](docs/capabilities.md). Design docs are in [docs/design/](docs/design).

## Run it in your AWS account

[deploy/README.md](deploy/README.md) is the guide:
- **Control plane:** copy `deploy/terraform/examples/self-hosted`, apply, and roll out a signed release with `deploy/scripts/rollout.sh`. It can use your existing VPC, DNS, certificate, Postgres, KMS keys, ECS cluster, permissions boundary and WAF.
- **Agents:** the `nightfix-agent` Terraform module (ECS Fargate) or the Helm chart in `deploy/helm` (EKS).
- **Sign-in:** any OpenID Connect provider (Okta, Google Workspace, Entra ID, Keycloak), Auth0 Organizations, or API keys only.

## Repository layout

```
cmd/                   nightfix (control plane), nightfix-agent, devstub (local stubs)
internal/controlplane  ingest, incidents, runs, dispatch, notifications, API, agent gateway
internal/agent         agent loop, verification, executors, redaction
internal/…             runbook parsing and linting, signing, OIDC/Auth0, CEL, database
migrations/            schema and row-level security (never edit a shipped migration)
deploy/                Terraform modules and examples, the Helm chart, rollout scripts
docs/                  what's built, and the design docs
examples/runbooks/     example runbooks
```

## Tests

```bash
make test        # starts a throwaway Postgres unless NIGHTFIX_TEST_ADMIN_DSN is set
make test-race   # what CI runs: race detector, shuffled order, coverage floor of 80%
```

Run them as a non-superuser admin (`CREATEROLE CREATEDB`), as CI does: a superuser bypasses row-level security. CI also runs govulncheck, gitleaks over the full history, Terraform validate, Helm lint, and both demos, checking that each one plays out as expected.

Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## How it's built

- The design is written down in [docs/design](docs/design) before it's built.
- Every change runs through CI: the race detector, shuffled test order, an 80% coverage floor, both end-to-end demos, Terraform and Helm validation, secret scanning over the full history, and a vulnerability check.
- The security-sensitive parts (signing, enrollment, sign-in, tenancy, the agent's sandboxing and redaction) have had several independent adversarial reviews, with every finding fixed and covered by a regression test.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
