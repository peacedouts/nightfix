# Security policy

Nightfix runs code in your AWS account, so we take reports seriously and would rather hear about something small than miss it.

## Reporting a vulnerability

Report privately, not in a public issue:
- through GitHub: **Security → Report a vulnerability** on this repository, or
- by email to **security@nightfix.dev**.

Include what you found, how to reproduce it, and the impact you think it has. We acknowledge reports within 3 business days and keep you updated until it's fixed. We'll credit you in the release notes unless you'd rather we didn't.

## Scope

In scope: the code in this repository (the control plane, the agent, the Terraform modules, the Helm chart, the release and rollout scripts) and the release artifacts built from it (images and the chart on GHCR).

Out of scope: someone's own deployment of Nightfix and how it's configured, nightfix.dev itself, and denial of service by volume.

## Supported versions

Fixes go into the latest release. Until 1.0, older releases don't get backports; upgrading is the fix. See [deploy/README.md](deploy/README.md) ("Releases and upgrades").

## Verifying what you run

Images and the Helm chart are signed with Sigstore by this repository's workflows. `deploy/scripts/rollout.sh` checks the signature before rolling out, and [deploy/README.md](deploy/README.md) shows how to verify a digest yourself.
