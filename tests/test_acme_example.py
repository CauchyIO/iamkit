import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # make `examples` importable

from examples.acme.config import build_acme_config
from iamkit.convention.loader import load_convention
from iamkit.export.terraform import TerraformExporter

ACME_CONVENTION = Path(__file__).parent.parent / "examples" / "acme" / "acme_iam.yaml"


def test_acme_config_validates() -> None:
    config = build_acme_config()
    assert set(config.users) == {"alice", "bob"}


def test_acme_exports_round_trip(tmp_path) -> None:
    exporter = TerraformExporter(build_acme_config(), github_org_default="acme-corp")
    exporter.write_entra_tfvars(str(tmp_path / "entra.auto.tfvars.json"))
    exporter.write_github_tfvars(str(tmp_path / "github.auto.tfvars.json"))
    entra = json.loads((tmp_path / "entra.auto.tfvars.json").read_text())
    github = json.loads((tmp_path / "github.auto.tfvars.json").read_text())
    assert len(entra["iam_security_groups"]) == 1
    assert github["github_teams"][0]["name"] == "engineering"
    assert github["github_teams"][0]["repositories"] == {"widget-factory": "push"}
    variables_tf = (tmp_path / "github-variables.tf").read_text()
    assert 'default     = "acme-corp"' in variables_tf


def test_acme_convention_ships_and_uses_every_rule() -> None:
    convention = load_convention(ACME_CONVENTION)
    assert convention.schema.convention == "acme_iam"
    used_rules = {rule.rule for rule in convention.schema.rules}
    assert used_rules == set(convention.registry.list_rules())


def test_acme_config_passes_acme_convention() -> None:
    convention = load_convention(ACME_CONVENTION)
    config = build_acme_config()
    resources = list(config.users.values()) + list(config.groups.values())
    for resource in resources:
        errors = convention.get_validation_errors(resource, include_advisory=True)
        assert errors == [], f"{resource.name}: {errors}"
