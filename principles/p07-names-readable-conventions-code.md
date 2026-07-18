---
type: Principle
title: Names Are Readable and Conventions Are Code
description: Every object's name makes its kind and purpose readable at a glance; the naming rules themselves live in a validated convention file, not a wiki.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P07
pillar: conventions
statement: "Every group and principal name follows the org's declared naming convention, and that convention is a machine-validated file in the config package."
covers:
  - convention:naming_pattern
  - convention:environment_suffix
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P07 — Names are readable and conventions are code

## Rationale

A name is the cheapest piece of governance metadata: `sg-engineering` tells a
reviewer what it is and roughly who should be in it before any tool is opened.
Conventions kept in a wiki drift the day they are written; conventions kept in
a validated YAML file fail the build when violated. Environment belongs in a
field, not a name suffix — a suffix forks the group per environment and turns
renames into destroy-recreate events.

## Implications

- **Technical**: the convention YAML (see `examples/acme/acme_iam.yaml`)
  declares per-type naming patterns enforced by `naming_pattern`;
  `environment_suffix` catches hardcoded `_dev`/`_acc`/`_prd` names.
- **Organizational**: settling the naming convention is a day-one decision
  for a new org — retrofitting names onto a live estate means recreating
  groups that access flows through (see `prevent_destroy` in IAM-P02).

## Exceptions

Objects whose names are fixed by an external system (vendor-created groups,
synced distribution lists) are recorded as existing/unmanaged rather than
renamed.

## Tensions

With brevity: convention prefixes make names longer. Settled in favor of
readability — names are read far more often than typed.

## Derivation

Restates naming-standard practice from Microsoft's Entra deployment guidance.
