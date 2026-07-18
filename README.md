# iamkit

IAM-as-code building blocks: define users, groups, and access policies once in a
Pydantic DSL; export them to Terraform tfvars consumed by reusable modules
(Entra ID, GitHub org) or push them through API executors (Linear).

Sibling of [brickkit](https://github.com/CauchyIO/brickkit) (Databricks governance).

```
your config package        ─→ IAMConfig (validated)
(see examples/acme)                │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
           entra.auto.tfvars  github.auto.tfvars  Graph API payloads
                    ▼              ▼
     terraform/modules/entra  terraform/modules/github
                    ▼              ▼
                Entra ID        GitHub Org
```

## Install

```bash
pip install "iamkit @ git+https://github.com/CauchyIO/iamkit.git@v0.1.1"
# or: uv add "iamkit @ git+https://github.com/CauchyIO/iamkit.git@v0.1.1"
```

## Quick start

Define your tenant (full example in [`examples/acme/`](examples/acme/)):

```python
from iamkit.models.base import MemberReference
from iamkit.models.config import IAMConfig
from iamkit.models.groups import SecurityGroup
from iamkit.models.principals import GitHubUserConfig, PlatformConfig, User

alice = User(
    name="alice",
    display_name="Alice Anvil",
    email="alice@acme.example",
    usage_location="NL",
    platform_config=PlatformConfig(github=GitHubUserConfig(handle="alice-acme")),
)

engineers = SecurityGroup(
    name="sg-engineering",
    members=[MemberReference(name="alice")],
    owners=[MemberReference(name="alice")],
)

config = IAMConfig(users={"alice": alice}, groups={"sg-engineering": engineers})
```

Export it:

```python
from iamkit.export.terraform import TerraformExporter

exporter = TerraformExporter(config, github_org_default="acme-corp")
exporter.write_entra_tfvars("terraform/entra/entra.auto.tfvars.json")
exporter.write_github_tfvars("terraform/github/github.auto.tfvars.json")
```

Apply it — your root module consumes the reusable modules:

```hcl
module "iam" {
  source = "github.com/CauchyIO/iamkit//terraform/modules/entra?ref=v0.1.1"

  iam_users_existing   = var.iam_users_existing
  iam_users_managed    = var.iam_users_managed
  iam_security_groups  = var.iam_security_groups
  iam_license_groups   = var.iam_license_groups
  iam_m365_groups      = var.iam_m365_groups
  iam_role_assignments = var.iam_role_assignments
}
```

Tenant-specific resources (branch protections, app registrations, one-off group
memberships) live alongside the module call in your root module; the module
exposes `user_object_ids` / `*_group_object_ids` / `team_node_ids` outputs to
wire them up.

## Principles and conventions

[`principles/`](principles/index.md) is the governance baseline: eight
principles (group-held access, lifecycle as code, tiered administration, CA
baseline, guest expiry, non-human identities, readable names, one namespace),
each mapping to its enforcement points in the model validators, convention
rules, and Terraform guards. For a new org, walk the catalog adopt/adapt/reject,
then express the outcome as a convention YAML.

Encode the settled naming and ownership rules in YAML
([`examples/acme/acme_iam.yaml`](examples/acme/acme_iam.yaml) is a complete
starting point) and validate every resource:

```python
from iamkit.convention.loader import load_convention

convention = load_convention("examples/acme/acme_iam.yaml")
for key, group in config.groups.items():
    for error in convention.get_validation_errors(group, include_advisory=True):
        print(f"[{key}] {error}")
```

## Development

```bash
uv sync
uv run pytest
```

`uv sync` automatically enables the repo's leak-guard git hooks
(`core.hooksPath = .githooks`), which block commits and pushes containing
tenant references before they leave your machine; the test suite refuses to
run if the hooks are disabled. The hooks read their pattern list from
`~/.config/iamkit/leak-patterns.txt` (override with `IAMKIT_LEAK_PATTERNS`),
one extended regex per line — the list itself is never committed and is
distributed to maintainers out of band. Without it the hooks warn and pass,
so outside contributors can commit normally; the leak-guard CI workflow,
which also runs on fork PRs, is the enforcing backstop.

## License

MIT © Cauchy
