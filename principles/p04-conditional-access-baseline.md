---
type: Principle
title: Conditional Access Is a Baseline That Targets Groups
description: A small set of tenant-wide Conditional Access policies — MFA for all, legacy auth blocked — targeting groups, with break-glass excluded.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P04
pillar: access
statement: "Conditional Access policies form a declared baseline, target groups rather than individuals, and always exclude the break-glass accounts."
covers:
  - model:ca_policy_references
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P04 — Conditional Access is a baseline that targets groups

## Rationale

Conditional Access sprawl is the portal-side mirror of individual grants:
policies accumulate per incident, target named users, and nobody can say what
the tenant's actual posture is. A declared baseline (MFA for all users, legacy
authentication blocked, stricter controls for admins) expressed against groups
keeps posture reviewable in one diff. A policy that references a principal or
group not in the config is a typo or a side channel — either way it fails
validation.

## Implications

- **Technical**: `ConditionalAccessPolicy` conditions reference config-defined
  users and groups only; unknown references fail at model time.
- **Organizational**: new access scenarios are handled by group membership,
  not by new per-person policies.

## Exceptions

Break-glass accounts are excluded from every CA policy — an exclusion that is
itself part of the declared baseline, not an omission.

## Tensions

With emergency lockdowns: incident-time policies are created portal-side
first. Settled the same way as IAM-P02 — retrofit into the package same-day.

## Derivation

Restates Microsoft Entra Conditional Access deployment guidance and CIS
Microsoft 365 Benchmark identity controls (MFA, legacy authentication).
