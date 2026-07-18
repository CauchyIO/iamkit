---
type: Principle
title: Administration Is Tiered and Break-Glass Stays Outside
description: Privileged roles are few, held by dedicated admin identities, and break-glass accounts are never managed by automation that could lock them out.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P03
pillar: administration
statement: "Global admin roles are held by at most a handful of dedicated identities; break-glass and board-level accounts are read-only data sources to IaC, never managed resources."
covers:
  - terraform:existing_users
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P03 — Administration is tiered and break-glass stays outside

## Rationale

An automation plane powerful enough to manage every account is powerful enough
to destroy every account. The accounts that recover the tenant — break-glass,
and any principal whose loss is unrecoverable — must sit outside the blast
radius of the tool: referenced read-only (`existing_users` data sources),
never owned. Microsoft's guidance converges on the same numbers everywhere:
two to four Global Administrators plus excluded break-glass accounts.

## Implications

- **Technical**: `iam_users_existing` principals are data sources; a
  `terraform destroy` cannot touch them. Admin role holders use dedicated
  admin identities, not daily-driver accounts.
- **Organizational**: break-glass credentials are custodied and tested on a
  calendar, outside this repo and outside the tenant's SSO path.

## Exceptions

None. An exception to this principle is the incident.

## Tensions

With completeness: the IaC view of the tenant is deliberately partial.
Settled in favor of the gap — the unmanaged remainder is enumerable and small.

## Derivation

Restates Microsoft Entra emergency-access ("break-glass") account guidance
and privileged-role tiering from the Azure Well-Architected security pillar.
