"""The public exporter must not bake in any specific org name."""

from iamkit.export.terraform import GITHUB_VARIABLE_SCHEMAS, TerraformExporter
from iamkit.models.config import IAMConfig


def _schema(name: str) -> dict:
    return next(s for s in GITHUB_VARIABLE_SCHEMAS if s["name"] == name)


def test_github_org_schema_has_no_hardcoded_default() -> None:
    assert "default" not in _schema("github_org")


def test_github_org_default_injected_when_provided(tmp_path) -> None:
    exporter = TerraformExporter(IAMConfig(), github_org_default="acme-corp")
    exporter.write_github_tfvars(str(tmp_path / "github.auto.tfvars.json"))
    variables_tf = (tmp_path / "github-variables.tf").read_text()
    assert 'default     = "acme-corp"' in variables_tf


def test_github_org_required_when_no_default(tmp_path) -> None:
    exporter = TerraformExporter(IAMConfig())
    exporter.write_github_tfvars(str(tmp_path / "github.auto.tfvars.json"))
    variables_tf = (tmp_path / "github-variables.tf").read_text()
    block = variables_tf.split('variable "github_org"')[1].split("}")[0]
    assert "default" not in block


def test_entra_and_github_variables_do_not_clobber(tmp_path) -> None:
    exporter = TerraformExporter(IAMConfig(), github_org_default="acme-corp")
    exporter.write_entra_tfvars(str(tmp_path / "entra.auto.tfvars.json"))
    exporter.write_github_tfvars(str(tmp_path / "github.auto.tfvars.json"))
    entra_tf = (tmp_path / "entra-variables.tf").read_text()
    github_tf = (tmp_path / "github-variables.tf").read_text()
    assert "iam_users_managed" in entra_tf
    assert "github_teams" in github_tf
