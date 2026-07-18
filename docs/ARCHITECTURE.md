# Architecture

## Flow

```
your config package        ─→ IAMConfig (validated)
(see examples/acme)                │
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
           entra.auto.tfvars  github.auto.tfvars  Graph API payloads
                    │              │              (shared mailboxes)
                    ▼              ▼
     terraform/modules/entra  terraform/modules/github
                    │              │
                    ▼              ▼
              Entra ID        GitHub Org
         (users, groups,   (members, teams,
          licenses)         repo permissions)
```

## Layers

### Config (source of truth — yours, not iamkit's)

Pure Python data objects. No logic, no side effects. You own a private config
package that instantiates iamkit models: users, group shells, memberships, and
access policies, assembled into one `IAMConfig`. `examples/acme` shows the pattern.

### Models (validation)

Pydantic V2 schemas in `iamkit.models`. Cross-validation happens in `IAMConfig`:
- All member references resolve to real principals
- No circular group nesting
- GitHub handles are unique
- License groups only contain users with `usage_location`

### Convention (naming/policy rules)

`iamkit.convention` loads a YAML convention file (naming patterns, required
attributes, ownership rules) and validates resources against it. The YAML is
tenant-specific and lives with your config, not in iamkit.

### Export (config → terraform)

`iamkit.export.terraform.TerraformExporter` converts `IAMConfig` into
`.auto.tfvars.json` + `variables.tf` files consumed by the Terraform modules. It
splits users into managed vs. existing, flattens group members, and derives GitHub
teams from access policies. `iamkit.export.graph_api.GraphAPIExporter` renders
Graph API payloads for resources Terraform cannot manage (shared mailboxes,
mailing lists).

### Terraform (infrastructure)

Two independent reusable modules:
- **terraform/modules/entra** — `azuread` provider: users, security groups,
  license groups, M365 groups, Azure RBAC role assignments
- **terraform/modules/github** — `github` provider: org settings, membership,
  teams, team-repo permissions

Your root modules pass the exported tfvars through and add tenant-specific
resources (branch protections, app registrations) alongside.

### Executors (API-based platforms)

For platforms without Terraform support, following the BaseExecutor pattern:
query current state → diff against desired → apply changes.

- **Linear** — `iamkit.executors.linear`: workspace membership, team assignment,
  role management via the GraphQL API

## Key decisions

- **Groups are the unit of access**, not individual users. Permissions flow:
  user → group → access policy → platform.
- **Unmanaged principals are data sources** (`managed=False`) — referenced,
  never created or destroyed.
- **Exports are deterministic** — same config in, byte-identical tfvars out, so
  diffs in CI are meaningful.
