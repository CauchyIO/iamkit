# Principle catalog

The IAM governance baseline iamkit enforces. Each principle's frontmatter is
machine-readable (id, pillar, statement, covers); `covers:` maps the principle
to its enforcement points across iamkit's three tiers:

- `convention:<rule>` — a rule in the convention registry (`src/iamkit/convention/rules.py`),
  settled per-org in the convention YAML (see `examples/acme/acme_iam.yaml`)
- `model:<validator>` — a hard `IAMConfig` validator (`src/iamkit/models/config.py`)
- `terraform:<guard>` — a plan-time guard in the Terraform modules

`tests/test_principles_catalog.py` keeps the mapping honest: every convention
rule must have exactly one parent principle, and every covers entry must
resolve to real code. A principle with `covers: []` is a declared enforcement
gap, kept loud on purpose.

For a new org, this catalog is the strategy conversation: walk it top to
bottom, adopt / adapt / reject each principle, then express the outcome in
your convention YAML and config package.

## Access

- [Access Is Held by Groups](p01-group-held-access.md) — every entitlement is held by a group with an owner; no grant targets an individual.
- [Conditional Access Is a Baseline That Targets Groups](p04-conditional-access-baseline.md) — a declared CA baseline against groups, break-glass excluded.

## Lifecycle

- [Identity Lifecycle Is Managed as Code](p02-lifecycle-as-code.md) — joiner/mover/leaver events are pull requests; records carry manager and usage_location.
- [Guests Are Sponsored and Expire](p05-guests-sponsored-expiring.md) — every external user has a sponsor and an end or review date.

## Administration

- [Administration Is Tiered and Break-Glass Stays Outside](p03-tiered-administration.md) — few privileged roles on dedicated identities; break-glass is never IaC-managed.
- [Non-Human Identities Are First-Class](p06-nonhuman-first-class.md) — automation runs as its own identity; shared access is delegated, never credential-shared.

## Conventions

- [Names Are Readable and Conventions Are Code](p07-names-readable-conventions-code.md) — names carry kind and purpose; the convention is a validated file.
- [Principals Share One Reference Namespace](p08-one-reference-namespace.md) — one name, one object, across every collection and platform handle.
