---
type: Principle
title: Non-Human Identities Are First-Class
description: Automation runs as service principals or managed identities, shared mailboxes are delegated rather than credential-shared, and no process authenticates as a person.
timestamp: 2026-07-19T00:00:00Z
id: IAM-P06
pillar: administration
statement: "Every non-human actor has its own modeled identity — service principal, managed identity, or shared mailbox with named delegates; no automation runs under a user account and no credential is shared."
covers:
  - model:shared_mailbox_delegates
informs: []
review:
  owner: catalog maintainer
  cadence: every release
---

# IAM-P06 — Non-human identities are first-class

## Rationale

Automation borrowed from a person breaks when the person leaves, and access
shared through a common password is unattributable by construction. Modeling
service principals, managed identities, and shared mailboxes as first-class
config objects gives every non-human actor an owner, a review surface, and a
revocation path. Delegation (named principals on a shared mailbox) preserves
attribution where a shared credential would erase it.

## Implications

- **Technical**: shared mailbox delegates must resolve to known principals;
  managed identities are group-joinable principals like any other. Prefer
  workload identity federation over client secrets where the platform allows.
- **Organizational**: "the team login" is retired; each automation gets an
  identity and an owning team.

## Exceptions

Vendor products that only support a single service account operate under a
dedicated (still non-personal) identity with custodied credentials.

## Tensions

With setup cost: a dedicated identity per automation is more objects to
manage. Settled in favor of attribution — objects are cheap, forensics on a
shared account are not.

## Derivation

Restates Microsoft Entra workload identity guidance and NIST SP 800-53 AC-2
requirements on shared-account attribution.
