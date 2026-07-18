"""Tests for export interfaces."""

import json

import pytest
from pydantic import ValidationError

from iamkit.models.base import MemberReference
from iamkit.models.config import IAMConfig
from iamkit.models.enums import GitHubOrgRole, LinearRole, PermissionLevel
from iamkit.models.access import (
    AccessPolicy,
    GitHubAccessSpec,
    GitHubOrgSettings,
    LinearAccessSpec,
)
from iamkit.models.groups import LicenseGroup, M365Group, SecurityGroup
from iamkit.models.license import LicenseSKU
from iamkit.models.principals import (
    ExternalUser,
    GitHubUserConfig,
    LinearUserConfig,
    PlatformConfig,
    SharedMailbox,
    User,
)
from iamkit.models.groups import MailingList
from iamkit.export.terraform import ENTRA_VARIABLE_SCHEMAS, TerraformExporter
from iamkit.export.graph_api import GraphAPIExporter


def _test_config() -> IAMConfig:
    return IAMConfig(
        users={
            "alice": User(
                name="alice",
                display_name="Alice Anvil",
                email="alice@acme.example",
                usage_location="NL",
                managed=False,
                platform_config=PlatformConfig(
                    github=GitHubUserConfig(handle="alice-acme", org_role=GitHubOrgRole.ADMIN),
                ),
            ),
            "bob": User(
                name="bob",
                display_name="Bob van Brakel",
                email="bob@acme.example",
                usage_location="NL",
                platform_config=PlatformConfig(
                    github=GitHubUserConfig(handle="BobAcme"),
                ),
            ),
        },
        groups={
            "sg-admin": SecurityGroup(
                name="sg-admin",
                members=[MemberReference(name="alice")],
            ),
            "license-o365-business-premium": LicenseGroup(
                name="license-o365-business-premium",
                sku="O365_BUSINESS_PREMIUM",
                members=[MemberReference(name="alice")],
            ),
            "acme": M365Group(
                name="acme",
                display_name="Company",
                members=[MemberReference(name="alice")],
            ),
        },
        access_policies={
            "FullAccess": AccessPolicy(
                name="FullAccess",
                github=GitHubAccessSpec(
                    team_name="FullAcme",
                    repositories={"brickkit": PermissionLevel.PUSH},
                ),
            ),
        },
        license_skus={
            "O365_BUSINESS_PREMIUM": LicenseSKU(
                sku_id="f245ecc8-75af-4f8e-b61f-27d8114de5f3",
                sku_part_number="O365_BUSINESS_PREMIUM",
                friendly_name="Microsoft 365 Business Premium",
            ),
        },
    )


class TestTerraformExporter:
    def test_export_entra_tfvars(self):
        config = _test_config()
        exporter = TerraformExporter(config)
        result = exporter.export_entra_tfvars()

        assert len(result["iam_users_existing"]) == 1
        assert result["iam_users_existing"][0]["name"] == "alice"
        assert len(result["iam_users_managed"]) == 1
        assert result["iam_users_managed"][0]["name"] == "bob"
        assert len(result["iam_security_groups"]) == 1
        assert len(result["iam_license_groups"]) == 1
        assert result["iam_license_groups"][0]["sku_id"] == "f245ecc8-75af-4f8e-b61f-27d8114de5f3"
        assert len(result["iam_m365_groups"]) == 1

    def test_export_github_tfvars(self):
        config = _test_config()
        exporter = TerraformExporter(config)
        result = exporter.export_github_tfvars()

        assert len(result["github_members"]) == 2
        usernames = {m["username"] for m in result["github_members"]}
        assert "alice-acme" in usernames
        assert "BobAcme" in usernames
        assert len(result["github_teams"]) == 1

    def test_to_json_produces_valid_json(self):
        config = _test_config()
        exporter = TerraformExporter(config)
        data = exporter.export_entra_tfvars()
        json_str = exporter.to_json(data)
        parsed = json.loads(json_str)
        assert parsed["iam_users_existing"][0]["name"] == "alice"


class TestEntraSchemaCoverage:
    def test_schemas_cover_all_exported_keys(self):
        exported = set(TerraformExporter(IAMConfig()).export_entra_tfvars().keys())
        declared = {s["name"] for s in ENTRA_VARIABLE_SCHEMAS}
        assert exported <= declared, f"undeclared: {exported - declared}"

    def test_external_users_exported_with_name_key(self):
        config = IAMConfig(
            external_users={
                "windmill": ExternalUser(
                    email="info@windmill.example", display_name="Windmill Trust",
                )
            }
        )
        result = TerraformExporter(config).export_entra_tfvars()
        assert result["iam_external_users"][0]["name"] == "windmill"


class TestLicenseSkuLookup:
    def test_sku_lookup_by_part_number_not_dict_key(self):
        config = IAMConfig(
            users={
                "alice": User(
                    name="alice", display_name="Alice Anvil",
                    email="alice@acme.example", usage_location="NL",
                )
            },
            groups={
                "license-e3": LicenseGroup(
                    name="license-e3", sku="SPE_E3",
                    members=[MemberReference(name="alice")],
                )
            },
            license_skus={
                "e3": LicenseSKU(  # dict key deliberately != part number
                    sku_id="05e9a617-0261-4cee-bb44-138d3ef5d965",
                    sku_part_number="SPE_E3",
                    friendly_name="Microsoft 365 E3",
                )
            },
        )
        result = TerraformExporter(config).export_entra_tfvars()
        assert result["iam_license_groups"][0]["sku_id"] == "05e9a617-0261-4cee-bb44-138d3ef5d965"

    def test_license_group_without_any_skus_fails_validation(self):
        with pytest.raises(ValidationError, match="unknown SKU"):
            IAMConfig(
                users={
                    "alice": User(
                        name="alice", display_name="Alice Anvil",
                        email="alice@acme.example", usage_location="NL",
                    )
                },
                groups={
                    "license-e3": LicenseGroup(
                        name="license-e3", sku="SPE_E3",
                        members=[MemberReference(name="alice")],
                    )
                },
            )


class TestGithubExportContract:
    def test_github_org_emitted_from_org_settings(self):
        config = IAMConfig(
            github_org_settings=GitHubOrgSettings(
                name="acme-corp", billing_email="billing@acme.example",
            )
        )
        result = TerraformExporter(config).export_github_tfvars()
        assert result["github_org"] == "acme-corp"

    def test_github_org_falls_back_to_exporter_default(self):
        result = TerraformExporter(
            IAMConfig(), github_org_default="acme-corp"
        ).export_github_tfvars()
        assert result["github_org"] == "acme-corp"

    def test_team_members_deduped(self):
        config = IAMConfig(
            users={
                "alice": User(
                    name="alice", display_name="Alice Anvil",
                    email="alice@acme.example", usage_location="NL",
                    platform_config=PlatformConfig(
                        github=GitHubUserConfig(handle="alice-acme")
                    ),
                )
            },
            groups={
                "sg-eng": SecurityGroup(
                    name="sg-eng", members=[MemberReference(name="alice")],
                )
            },
            access_policies={
                "eng": AccessPolicy(
                    name="eng", group="sg-eng",
                    github=GitHubAccessSpec(
                        team_name="eng", external_members=["alice-acme"],
                    ),
                )
            },
        )
        result = TerraformExporter(config).export_github_tfvars()
        assert result["github_teams"][0]["members"] == ["alice-acme"]


class TestGraphAPIExporter:
    def test_mailing_list_payload(self):
        ml = MailingList(
            name="team",
            display_name="Team List",
            email_address="team@acme.example",
        )
        payload = GraphAPIExporter.mailing_list_payload(ml)
        assert payload["mailEnabled"] is True
        assert payload["securityEnabled"] is False
        assert payload["mail"] == "team@acme.example"

    def test_shared_mailbox_payload(self):
        mb = SharedMailbox(
            name="support",
            email_address="support@acme.example",
            display_name="Support Mailbox",
        )
        payload = GraphAPIExporter.shared_mailbox_payload(mb)
        assert payload["displayName"] == "Support Mailbox"
        assert "SharedMailbox" in payload["resourceBehaviorOptions"]
