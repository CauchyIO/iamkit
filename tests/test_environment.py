"""Tests for optional environment awareness on groups.

The resolved-name contract ({name}_{env}) must match what brickkit's
MemberReference.resolved_name produces, since Entra groups sync into
Databricks via SCIM and are looked up by that name.
"""

import pytest

from iamkit.convention.loader import IAMConvention
from iamkit.convention.schema import ConventionSchema, RuleMode
from iamkit.export.terraform import TerraformExporter
from iamkit.models.config import IAMConfig
from iamkit.models.enums import Environment
from iamkit.models.groups import SecurityGroup


class TestEnvironmentEnum:
    def test_environments_have_lowercase_suffix_values(self):
        assert Environment.DEV.value == "dev"
        assert Environment.ACC.value == "acc"
        assert Environment.PRD.value == "prd"


class TestSecurityGroupEnvironment:
    def test_environment_defaults_to_none(self):
        group = SecurityGroup(name="sg-engineering")
        assert group.environment is None

    def test_resolved_name_without_environment_is_plain_name(self):
        group = SecurityGroup(name="sg-engineering")
        assert group.resolved_name == "sg-engineering"

    def test_resolved_name_with_environment_appends_suffix(self):
        group = SecurityGroup(name="sg-databricks-quant", environment=Environment.DEV)
        assert group.resolved_name == "sg-databricks-quant_dev"

    def test_environment_accepts_all_environments(self):
        for env, suffix in [
            (Environment.DEV, "_dev"),
            (Environment.ACC, "_acc"),
            (Environment.PRD, "_prd"),
        ]:
            group = SecurityGroup(name="sg-x", environment=env)
            assert group.resolved_name == f"sg-x{suffix}"


class TestExporterUsesResolvedName:
    def test_security_group_tfvars_name_carries_environment_suffix(self):
        config = IAMConfig(
            groups={
                "sg-databricks-quant-dev": SecurityGroup(
                    name="sg-databricks-quant", environment=Environment.DEV
                ),
                "sg-engineering": SecurityGroup(name="sg-engineering"),
            }
        )
        exporter = TerraformExporter(config)
        tfvars = exporter.export_entra_tfvars()
        names = {g["name"] for g in tfvars["iam_security_groups"]}
        assert names == {"sg-databricks-quant_dev", "sg-engineering"}


class TestLicenseGroupInheritsEnvironment:
    def test_license_group_tfvars_name_uses_resolved_name(self):
        from iamkit.models.groups import LicenseGroup
        from iamkit.models.license import LicenseSKU

        config = IAMConfig(
            groups={
                "license-dynamics": LicenseGroup(
                    name="license-dynamics", sku="dyn365", environment=Environment.ACC
                )
            },
            license_skus={
                "dyn365": LicenseSKU(
                    sku_id="guid-123",
                    sku_part_number="dyn365",
                    friendly_name="Dynamics 365",
                )
            },
        )
        tfvars = TerraformExporter(config).export_entra_tfvars()
        assert tfvars["iam_license_groups"][0]["name"] == "license-dynamics_acc"


class TestEnvironmentSuffixRule:
    def _convention(self, mode: str = "enforced") -> IAMConvention:
        schema = ConventionSchema(
            convention="test",
            rules=[RuleMode(rule="environment_suffix", mode=mode)],
        )
        return IAMConvention(schema=schema)

    def test_hardcoded_env_suffix_without_environment_field_fails(self):
        group = SecurityGroup(name="sg-databricks-quant_dev")
        errors = self._convention().get_validation_errors(group)
        assert len(errors) == 1
        assert "environment" in errors[0]

    def test_environment_field_set_passes(self):
        group = SecurityGroup(name="sg-databricks-quant", environment=Environment.DEV)
        errors = self._convention().get_validation_errors(group)
        assert errors == []

    def test_plain_group_without_environment_passes(self):
        group = SecurityGroup(name="sg-engineering")
        errors = self._convention().get_validation_errors(group)
        assert errors == []
