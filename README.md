# Nightfix

Open-source incident response for teams on AWS. Alerts become incidents, and runbooks fix the problem before anyone is paged. It all runs in your own AWS account: the control plane, its database and keys, and an agent in your VPC or cluster that runs signed runbooks under an IAM role you scope. Nothing calls home.

> A CloudWatch alarm fires → an incident opens → a restart runbook runs through the agent → the alarm clears → the incident resolves. **Nobody is paged.** If the fix doesn't work, your pager gets the incident with what was tried.

## Try it locally

Needs Go 1.24+, PostgreSQL 15+ (`initdb`, `pg_ctl`, `psql`), `curl` and `python3`.

```bash
make demo        # the alarm fixes itself; nobody is paged
make demo-fail   # the fix fails; on-call is paged, then the page resolves
```

The demo runs a throwaway Postgres, the control plane, a real agent over mutual TLS, and stubs for ECS, SNS, Slack and PagerDuty, then prints the incident timeline and what Slack and PagerDuty received.

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
- **Runbooks** are YAML, linted and signed on publish. One that may run before paging holds the page while it works; if the alert clears, nobody is woken. Risky steps wait for approval in Slack.
- **Agents** connect out over mutual TLS, enroll with their IAM role (no tokens), check every step against the runbook's signature and their own allowlist, and redact secrets from what they send back.
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

Run them as a non-superuser admin (`CREATEROLE CREATEDB`), as CI does: a superuser bypasses row-level security. CI also runs govulncheck, gitleaks over the full history, Terraform validate, Helm lint, and both demos with a check that their story happened.

Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
