---
title: Sign in with Auth0
description: Connect your team's sign-in, map groups to teams, and scope what each team can do.
---

Your team signs in to Nightfix through Auth0, using your own identity provider. Nightfix decides what each person can do with roles you assign.

## Roles

| Role | Can do |
|---|---|
| Owner | Everything, including granting admin and owner |
| Admin | Manage services, integrations, agents, teams and roles |
| Responder | Run runbooks, publish runbooks, acknowledge and resolve incidents |
| Viewer | See incidents, runbooks and runs. Viewers are free |

Anyone who signs in without a role is a viewer.

## Scopes

A role can be limited by team, runbook tag and environment. For example, to let the payments team run payments runbooks everywhere except production:

```json
{
  "subject_type": "team",
  "subject": "payments",
  "role": "responder",
  "scope": { "tags": ["payments"], "env": ["staging", "dev"] }
}
```

Someone with only that role can't run a runbook that targets production, and can't take over another team's runbook by publishing a new version of it.

## Teams from your identity provider

Link a team to a group in your identity provider. People join and leave the team automatically as their group membership changes, the next time they sign in.

## Setup

1. Your Nightfix org is linked to an Auth0 Organization. We set this up with you during onboarding.
2. Create teams and link each one to a group from your identity provider.
3. Grant roles to teams, or to individual people by email after they first sign in.
