---
type: Principle
title: Guests Are Sponsored and Expire
description: Every B2B guest has an internal sponsor and an end date; guest access is reviewed, never permanent.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P05
pillar: lifecycle
statement: "Every external user is attached to a named internal sponsor and an expiry or review date; a guest without both is a finding."
covers: []
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P05 — Guests are sponsored and expire

## Rationale

Guest accounts are the longest-lived form of forgotten access: the project
ends, the vendor rotates staff, and the invitation outlives them all. A guest
with a sponsor has someone who will answer "do they still need this?"; a guest
with an expiry date gets that question asked automatically. Without both, the
only removal path is an audit that never comes.

## Implications

- **Technical**: `ExternalUser` is invitation-based; group membership is the
  only access path (IAM-P01), so revocation is one membership removal.
  Sponsor and review-date fields are an open enforcement gap — this principle
  currently has no covering rule, deliberately visible as `covers: []`.
- **Organizational**: sponsoring a guest is accepting an obligation; the
  review cadence belongs to the sponsor, not to a central team.

## Exceptions

Long-lived partner integrations may carry a standing review (e.g. annual)
instead of an expiry, with the sponsor recorded.

## Tensions

With collaboration friction: expiry interrupts working guests. Settled in
favor of expiry — renewal is one PR; forgotten access is unbounded risk.

## Derivation

Restates Microsoft Entra B2B collaboration guidance and access-review
practice from the CIS Microsoft 365 Benchmark (guest user reviews).
