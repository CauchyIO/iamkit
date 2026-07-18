"""ACME Corp — a fictional tenant showing the iamkit config pattern.

Mirrors the recommended layout: identities, group shells, memberships wired at
assembly time, access policies mapping groups to platforms.
"""

from iamkit.models.access import AccessPolicy, GitHubAccessSpec
from iamkit.models.base import MemberReference
from iamkit.models.config import IAMConfig
from iamkit.models.enums import PermissionLevel
from iamkit.models.groups import LicenseGroup, SecurityGroup
from iamkit.models.license import LicenseSKU
from iamkit.models.principals import GitHubUserConfig, PlatformConfig, User

alice = User(
    name="alice",
    display_name="Alice Anvil",
    email="alice@acme.example",
    usage_location="NL",
    platform_config=PlatformConfig(github=GitHubUserConfig(handle="alice-acme")),
)

bob = User(
    name="bob",
    display_name="Bob Beaker",
    email="bob@acme.example",
    usage_location="NL",
    platform_config=PlatformConfig(github=GitHubUserConfig(handle="bob-acme")),
)

engineers = SecurityGroup(
    name="sg-engineering",
    display_name="Engineering",
    description="All ACME engineers",
    members=[MemberReference(name="alice"), MemberReference(name="bob")],
    owners=[MemberReference(name="alice")],
)

license_e3 = LicenseGroup(
    name="license-e3",
    display_name="License: E3",
    sku="SPE_E3",
    members=[MemberReference(name="alice"), MemberReference(name="bob")],
)

engineering_access = AccessPolicy(
    name="engineering-access",
    group="sg-engineering",
    github=GitHubAccessSpec(
        team_name="engineering",
        repositories={"widget-factory": PermissionLevel.PUSH},
    ),
)


def build_acme_config() -> IAMConfig:
    return IAMConfig(
        users={"alice": alice, "bob": bob},
        groups={"sg-engineering": engineers, "license-e3": license_e3},
        access_policies={"engineering-access": engineering_access},
        license_skus={
            "SPE_E3": LicenseSKU(
                sku_id="05e9a617-0261-4cee-bb44-138d3ef5d965",
                sku_part_number="SPE_E3",
                friendly_name="Microsoft 365 E3",
            ),
        },
    )
