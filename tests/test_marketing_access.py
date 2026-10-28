import json

import pytest
from pydantic import ValidationError

from iamkit.export import export_marketing_bindings
from iamkit.models import AccessPolicy, IAMConfig, MarketingAccessSpec, MarketingRole, SecurityGroup
from iamkit.models.enums import Environment
from iamkit.models.groups import M365Group

TENANT = "11111111-1111-4111-8111-111111111111"
GROUP = "22222222-2222-4222-8222-222222222222"


def config(spec=None, **group_options):
    return IAMConfig(
        groups={"sg-admin": SecurityGroup(name="sg-admin", **group_options)},
        access_policies={"admins": AccessPolicy(
            name="admins", group="sg-admin", marketing=spec,
        )},
    )


def test_roles_defaults_and_json_roundtrip():
    spec = MarketingAccessSpec(workspaces={"acme": "owner", "other": MarketingRole.VIEWER})
    assert spec.workspaces["acme"] is MarketingRole.OWNER
    assert spec.operator is False
    assert MarketingAccessSpec.model_validate_json(spec.model_dump_json()) == spec
    assert AccessPolicy(name="old-policy").marketing is None
    first, second = MarketingAccessSpec(), MarketingAccessSpec()
    first.workspaces["acme"] = MarketingRole.OWNER
    assert second.workspaces == {}


@pytest.mark.parametrize("workspaces", [{"": "owner"}, {"*": "owner"}, {"ACME": "owner"}, {"acme": "admin"}])
def test_invalid_workspace_or_role(workspaces):
    with pytest.raises(ValidationError):
        MarketingAccessSpec(workspaces=workspaces)


@pytest.mark.parametrize("group,groups", [
    (None, {}), ("sg-missing", {}),
    ("team", {"team": M365Group(name="team")}),
])
def test_marketing_requires_a_known_security_group(group, groups):
    with pytest.raises(ValidationError):
        IAMConfig(groups=groups, access_policies={"bad": AccessPolicy(
            name="bad", group=group, marketing=MarketingAccessSpec(workspaces={"acme": "owner"}),
        )})


def test_export_is_deterministic_scoped_and_json_serializable():
    cfg = config(MarketingAccessSpec(workspaces={"zulu": "viewer", "acme": "owner"}, operator=True))
    result = export_marketing_bindings(cfg, entra_tenant_id=TENANT)
    assert result == {"version": 1, "bindings": [{
        "policy": "admins", "entra_tenant_id": TENANT, "external_group": "sg-admin",
        "workspaces": {"acme": "owner", "zulu": "viewer"}, "operator": True,
    }]}
    assert list(result["bindings"][0]["workspaces"]) == ["acme", "zulu"]
    assert json.loads(json.dumps(result)) == result
    restored = IAMConfig.model_validate_json(cfg.model_dump_json())
    assert export_marketing_bindings(restored, entra_tenant_id=TENANT) == result


def test_export_resolves_environment_or_object_id_explicitly():
    cfg = config(MarketingAccessSpec(operator=True), environment=Environment.PRD)
    assert export_marketing_bindings(cfg, entra_tenant_id=TENANT)["bindings"][0]["external_group"] == "sg-admin_prd"
    assert export_marketing_bindings(cfg, entra_tenant_id=TENANT, group_ids={"sg-admin": GROUP})["bindings"][0]["external_group"] == GROUP
    with pytest.raises(KeyError):
        export_marketing_bindings(cfg, entra_tenant_id=TENANT, group_ids={})
    with pytest.raises(ValueError):
        export_marketing_bindings(cfg, entra_tenant_id="")


@pytest.mark.parametrize("spec", [None, MarketingAccessSpec()])
def test_export_does_not_infer_access(spec):
    assert export_marketing_bindings(config(spec), entra_tenant_id=TENANT) == {"version": 1, "bindings": []}
