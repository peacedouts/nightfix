# Changelog

Versions follow [semantic versioning](https://semver.org); what each part promises for upgrades is in `deploy/README.md` ("Releases and upgrades"). The release workflow publishes the section whose heading matches the version, so add one before releasing. Entries under "Unreleased" move into it.

## Unreleased

## [0.1.0]

The first versioned release.

- **Self-hosted control plane** as a Terraform module (`deploy/terraform/modules/nightfix-control-plane`) for a client's own AWS account. It can bring its own VPC, DNS, certificate, Postgres, KMS keys, alarm topic, ECS cluster, IAM path and permissions boundary, log encryption and export, VPC endpoints and WAF. Signed releases are rolled out with `deploy/scripts/rollout.sh`.
- **Agent** as a Terraform module (ECS Fargate) or a Helm chart (Kubernetes, with EKS Pod Identity or IRSA). It enrolls with its IAM role, verifies signed runbooks, and redacts secrets from output. Locally set controls limit what it runs whatever the control plane says: a pinned signing key, an allowlist of runbook digests (`allowlist_mode = "enforce"`), and the step types it may run (`step_types`, e.g. no shell).
- **Slack apps** are registered per workspace by owners, one active app per workspace, and a Slack user's link works only through the app it was made with (migrations 0030–0031 drop links in orgs with several apps and archive duplicate apps; relink with `/nightfix link`).
- **Terraform 1.12 or newer** for the control-plane module (its validations rely on 1.12's short-circuiting `||`).
- **Sign-in** through Auth0 Organizations or any OpenID Connect provider (Okta, Google Workspace, Entra ID, Keycloak), or with API keys only. Only tokens issued to the configured client IDs are accepted (`auth0_client_ids`, `oidc.client_ids`).
- Alert ingest (CloudWatch through SNS, signed webhooks), routing, incidents, remediation before paging, approvals in Slack, PagerDuty and Slack notifications, scoped RBAC, and a hash-chained audit log.
