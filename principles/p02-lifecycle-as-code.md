---
type: Principle
title: Identity Lifecycle Is Managed as Code
description: Joiner, mover, and leaver events are pull requests against one source of truth; user records carry the attributes downstream processes depend on.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P02
pillar: lifecycle
statement: "Every identity is created, changed, and retired through the version-controlled config package; user records must carry manager and usage_location so licensing and approval chains never stall."
covers:
  - convention:require_usage_location
  - model:manager_references
  - model:license_groups
  - terraform:prevent_destroy
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P02 — Identity lifecycle is managed as code

## Rationale

IAM estates rot through side channels: the portal edit during an incident, the
leaver whose account outlives their contract. When the config package is the
only write path, every joiner/mover/leaver event is a reviewed diff with an
author and a timestamp. Incomplete records stall downstream automation —
license assignment fails without `usage_location`, approval flows fail without
`manager` — so completeness is validated at model time, not discovered at
apply time.

## Implications

- **Technical**: the leaver path is deliberate — `prevent_destroy` on groups
  forces destructive changes to be explicit, and account disablement
  (`account_enabled: false`) precedes deletion.
- **Organizational**: HR events must reach the config package; a leaver PR is
  part of offboarding, not an afterthought.

## Exceptions

Password and name self-service changes flow tenant-side by design
(`ignore_changes` on those attributes) — the config package owns structure,
not personal attributes.

## Tensions

With incident response: portal edits are faster in the moment. Settled in
favor of code — an incident edit that matters gets retrofitted into the
package the same day.

## Derivation

Restates Microsoft Entra identity lifecycle (joiner-mover-leaver) guidance
and NIST SP 800-53 AC-2 (account management) automation controls.
