---
type: Principle
title: Access Is Held by Groups
description: Platform access, roles, and licenses are granted to groups, never to individual principals — individual grants accumulate with churn into an unadministrable estate.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P01
pillar: access
statement: "Every entitlement — platform access, role assignment, license — must be held by a group; no grant may target an individual principal."
covers:
  - convention:group_must_have_owner
  - model:member_references
  - model:group_memberships
  - model:circular_nesting
  - model:access_policies
  - terraform:membership_guard
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P01 — Access is held by groups

## Rationale

Individual grants survive staff churn silently: nobody reviews them, nobody
revokes them, and after two years of joiners and leavers the estate cannot be
audited. Group-held access makes every entitlement reviewable (list the group),
revocable (leave the group), and survivable (the group outlives its members).
An ownerless group is the same failure one level up — an entitlement nobody
answers for — so every group must have at least one owner.

## Implications

- **Technical**: `AccessPolicy` maps groups (never users) to platform access;
  role assignments and licenses attach to security groups; every membership
  reference must resolve or the plan fails loudly (`membership_guard`).
- **Organizational**: teams own their groups' membership; ownership is part of
  the group definition, not tribal knowledge.

## Exceptions

Break-glass accounts hold direct role assignments by design — they must work
when group resolution does not. They live outside IaC entirely (see IAM-P03).

## Tensions

With onboarding speed: group-mediated access adds a membership step. Settled
in favor of the group — the membership step is the audit trail.

## Derivation

Restates Microsoft Entra guidance on group-based access management and
group-based licensing, and CIS Microsoft 365 Benchmark role-assignment
controls.
