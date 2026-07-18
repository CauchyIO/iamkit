---
type: Principle
title: Principals Share One Reference Namespace
description: Users, service principals, managed identities, external users, shared mailboxes, and groups are referenced by bare name everywhere — so a name may exist in only one collection, and platform handles must be unique.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P08
pillar: conventions
statement: "A name identifies exactly one object across all principal and group collections, and platform identities (e.g. GitHub handles) map one-to-one to principals."
covers:
  - model:namespace_collisions
  - model:github_handles_unique
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P08 — Principals share one reference namespace

## Rationale

Memberships, owners, delegates, and exported tfvars all reference objects by
bare name. If `engineering` names both a user and a group, every reference to
it is ambiguous, and the Terraform `principal_object_ids` merge would resolve
the ambiguity silently — by shadowing. Ambiguity in an IAM system is not a
style problem; it decides who gets access. The same logic applies across
platforms: a GitHub handle claimed by two users makes team membership
unattributable.

## Implications

- **Technical**: `IAMConfig` rejects any name appearing in more than one
  collection and any duplicate GitHub handle at model time, before export.
- **Organizational**: the namespace is org-wide vocabulary; name allocation
  follows the naming convention (IAM-P07), which keeps collisions structurally
  unlikely (`sg-` groups cannot collide with user mnemonics).

## Exceptions

None. A collision has no legitimate reading.

## Tensions

With natural naming: the info mailbox and the info M365 group both "want" the
name `info`. Settled by the type-prefix convention — the group is `grp-info`
or similar; the namespace stays flat and unambiguous.

## Derivation

Internal to iamkit's reference model — the flat-namespace consequence of
referencing objects by bare name in members, owners, delegates, and tfvars.
