# Contributing to Nightfix

Thanks for helping. Bug reports, fixes, docs and runbook examples are all welcome.

## Before you start

- **Bugs and small fixes:** open a pull request, or an issue first if you're unsure it's a bug.
- **New features or design changes:** open an issue first. Nightfix runs code in people's AWS accounts, so changes to signing, enrollment, permissions or what the agent will run get discussed before they're written. The design docs in [docs/design](docs/design) are the reference.
- **Security issues:** don't open an issue; see [SECURITY.md](SECURITY.md).

## Building and testing

Needs Go 1.24+ and PostgreSQL 15+ (`initdb`, `pg_ctl`, `psql`).

```bash
make test        # starts a throwaway Postgres on port 54329
make test-race   # what CI runs: race detector, shuffled order, coverage floor
make lint        # go vet and gofmt
make demo        # the end-to-end demo
```

`make test` connects as the throwaway server's superuser. Before opening a PR, also run the tests the way CI does, as a non-superuser admin, because a superuser bypasses row-level security and some failures only show up without it:

```bash
DSN=$(scripts/dev-postgres.sh start)   # the throwaway server's superuser
psql "$DSN" -c "CREATE ROLE rds_admin LOGIN PASSWORD 'rds' CREATEROLE CREATEDB NOSUPERUSER" -c "GRANT pg_signal_backend TO rds_admin"
NIGHTFIX_TEST_ADMIN_DSN="postgres://rds_admin:rds@127.0.0.1:54329/postgres?sslmode=disable" make test-race
```

If you change Terraform, run `terraform fmt -recursive deploy/terraform`. If you change the Helm chart, run `helm lint --strict` on it.

## Rules that keep the codebase safe

- **Never edit a migration that has been released.** Add a new one; `migrations/frozen_test.go` enforces this.
- **New tenant tables get row-level security** like the existing ones, and tests prove isolation.
- **Alert data reaches runbook steps only through declared parameters** with a pattern or enum.
- **Don't describe something as working until it is.** Docs and comments say what the code does today.

## Sign your commits off (DCO)

Contributions are accepted under the [Apache License 2.0](LICENSE), with a [Developer Certificate of Origin](https://developercertificate.org) sign-off: by adding a `Signed-off-by` line you certify that you wrote the change or otherwise have the right to submit it under that license.

```bash
git commit -s -m "Fix the thing"
```

Use a name and an email you're happy to publish. GitHub's no-reply address works (`ID+username@users.noreply.github.com`); CI rejects commits whose author or committer is any other address.

## Pull requests

- Keep each PR to one change, with tests for new behaviour.
- Say what changed and why in the description; link the issue.
- CI must be green (tests, demo, Terraform, Helm, secret scanning, govulncheck).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
