"""Tests for the IAM DSL models using real inventory data from Acme."""

import pytest

from iamkit.models.enums import (
    CAState,
    GitHubOrgRole,
    GroupType,
    LinearRole,
    PermissionLevel,
    PrincipalType,
)
from iamkit.models.base import MemberReference, IdentityMapping
from iamkit.models.principals import (
    ExternalUser,
    GitHubUserConfig,
    LinearUserConfig,
    ManagedIdentity,
    PlatformConfig,
    ServicePrincipal,
    SharedMailbox,
    User,
)
from iamkit.models.groups import LicenseGroup, M365Group, MailingList, SecurityGroup
from iamkit.models.access import AccessPolicy, GitHubAccessSpec, LinearAccessSpec, SharePointAccessSpec
from iamkit.models.conditional_access import (
    CAConditions,
    CAConditionUsers,
    CAGrantControls,
    ConditionalAccessPolicy,
)
from iamkit.models.license import LicenseAssignment, LicenseSKU
from iamkit.models.config import AppRegistration, IAMConfig


# --- Fixtures based on real inventory data ---


def _acme_users() -> dict[str, User]:
    return {
        "alice": User(
            name="alice",
            display_name="Alice Anvil",
            email="alice@acme.example",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="alice-acme", org_role=GitHubOrgRole.ADMIN),
                linear=LinearUserConfig(email="alice@acme.example", role=LinearRole.ADMIN),
            ),
            group_memberships=["sg-admin", "license-o365-business-premium"],
        ),
        "carol": User(
            name="carol",
            display_name="Carol Papakosta",
            email="carol@acme.example",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="carolpapakosta"),
                linear=LinearUserConfig(email="carol@acme.example"),
            ),
            group_memberships=["sg-admin", "license-o365-business-premium"],
        ),
        "dana": User(
            name="dana",
            display_name="Dana Vechtomova",
            email="dana@acme.example",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="mvechtomova", org_role=GitHubOrgRole.ADMIN),
                linear=LinearUserConfig(email="dana@acme.example"),
            ),
            group_memberships=["sg-admin", "license-o365-business-premium"],
        ),
        "steven": User(
            name="steven",
            display_name="Steven Kempers",
            email="steven@acme.example",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="steveles"),
                linear=LinearUserConfig(email="steven@acme.example"),
            ),
            group_memberships=["license-o365-business-premium"],
        ),
        "bob": User(
            name="bob",
            display_name="Bob van Brakel",
            email="bob@acme.example",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="BobAcme"),
                linear=LinearUserConfig(email="bob@acme.example"),
            ),
            group_memberships=["license-o365-business-premium"],
        ),
    }


def _acme_groups() -> dict[str, SecurityGroup | LicenseGroup | M365Group]:
    return {
        "sg-admin": SecurityGroup(
            name="sg-admin",
            display_name="Acme Administrators",
            members=[
                MemberReference(name="alice"),
                MemberReference(name="carol"),
                MemberReference(name="dana"),
            ],
        ),
        "license-o365-business-premium": LicenseGroup(
            name="license-o365-business-premium",
            display_name="License: Microsoft 365 Business Premium",
            sku="O365_BUSINESS_PREMIUM",
            members=[
                MemberReference(name="alice"),
                MemberReference(name="carol"),
                MemberReference(name="dana"),
                MemberReference(name="steven"),
                MemberReference(name="bob"),
            ],
        ),
        "acme": M365Group(
            name="acme",
            display_name="The company wide channel",
            members=[
                MemberReference(name="carol"),
                MemberReference(name="dana"),
                MemberReference(name="bob"),
                MemberReference(name="steven"),
            ],
        ),
    }


def _acme_license_skus() -> dict[str, LicenseSKU]:
    return {
        "O365_BUSINESS_PREMIUM": LicenseSKU(
            sku_id="f245ecc8-75af-4f8e-b61f-27d8114de5f3",
            sku_part_number="O365_BUSINESS_PREMIUM",
            friendly_name="Microsoft 365 Business Premium",
        ),
        "EXCHANGESTANDARD": LicenseSKU(
            sku_id="4b9405b0-7788-4568-add1-99614e613b69",
            sku_part_number="EXCHANGESTANDARD",
            friendly_name="Exchange Online (Plan 1)",
        ),
    }


def _minimal_config(**overrides) -> IAMConfig:
    kwargs = {
        "users": _acme_users(),
        "groups": _acme_groups(),
        "license_skus": _acme_license_skus(),
    }
    kwargs.update(overrides)
    return IAMConfig(**kwargs)


# --- User model tests ---


class TestUser:
    def test_create_user_with_platform_config(self):
        user = User(
            name="alice",
            display_name="Alice Anvil",
            email="alice@acme.example",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="alice-acme", org_role=GitHubOrgRole.ADMIN),
                linear=LinearUserConfig(email="alice@acme.example", role=LinearRole.ADMIN),
            ),
        )
        assert user.platform_config.github.handle == "alice-acme"
        assert user.platform_config.linear.role == LinearRole.ADMIN

    def test_identity_mapping(self):
        user = User(
            name="alice",
            display_name="Alice Anvil",
            email="alice@acme.example",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="alice-acme"),
                linear=LinearUserConfig(email="alice@acme.example"),
            ),
        )
        mapping = user.identity_mapping
        assert mapping.entra_upn == "alice@acme.example"
        assert mapping.github_handle == "alice-acme"
        assert mapping.linear_email == "alice@acme.example"

    def test_invalid_email_rejected(self):
        with pytest.raises(ValueError, match="Invalid email"):
            User(name="bad", display_name="Bad", email="not-an-email")

    def test_optional_fields_default_none(self):
        user = User(name="test", display_name="Test", email="test@acme.example")
        assert user.department is None
        assert user.job_title is None
        assert user.manager is None
        assert user.usage_location is None


# --- Group model tests ---


class TestGroups:
    def test_security_group_add_user(self):
        group = SecurityGroup(name="TestGroup")
        group.add_user("alice")
        assert len(group.members) == 1
        assert group.members[0].name == "alice"
        assert group.members[0].principal_type == PrincipalType.USER

    def test_security_group_add_nested_group(self):
        group = SecurityGroup(name="Parent")
        group.add_nested_group("Child")
        assert group.members[0].principal_type == PrincipalType.GROUP

    def test_license_group_naming_enforced(self):
        with pytest.raises(ValueError, match="must start with 'license-'"):
            LicenseGroup(name="BadName", sku="O365_BUSINESS_PREMIUM")

    def test_license_group_valid(self):
        group = LicenseGroup(
            name="license-m365-e5",
            sku="M365_E5",
        )
        assert group.type == GroupType.LICENSE
        assert group.sku == "M365_E5"

    def test_mailing_list_email_validated(self):
        with pytest.raises(ValueError, match="Invalid email"):
            MailingList(name="test", email_address="bad")

    def test_m365_group(self):
        group = M365Group(
            name="Acme",
            display_name="The company wide channel",
            members=[MemberReference(name="alice")],
        )
        assert group.type == GroupType.M365


# --- External user tests ---


class TestExternalUser:
    def test_create_external_user(self):
        eu = ExternalUser(
            email="info@windmill.example",
            display_name="Windmill Trust",
        )
        assert eu.send_invitation is True
        assert eu.invitation_redirect_url == "https://myapps.microsoft.com"


# --- SharedMailbox tests ---


class TestSharedMailbox:
    def test_create_shared_mailbox(self):
        mb = SharedMailbox(
            name="team",
            email_address="team@acme.example",
            display_name="Team Mailbox",
            delegates=["alice", "carol"],
        )
        assert mb.delegates == ["alice", "carol"]


# --- AccessPolicy tests ---


class TestAccessPolicy:
    def test_access_policy_with_github(self):
        policy = AccessPolicy(
            name="FullAcme",
            github=GitHubAccessSpec(
                team_name="FullAcme",
                repositories={"brickkit": PermissionLevel.PUSH},
            ),
            linear=LinearAccessSpec(
                teams=["AcmeEng"],
                role=LinearRole.MEMBER,
            ),
        )
        assert policy.github.team_name == "FullAcme"
        assert policy.linear.teams == ["AcmeEng"]

    def test_access_policy_board_level(self):
        policy = AccessPolicy(
            name="BoardAccess",
            github=GitHubAccessSpec(
                team_name="AcmeBoard",
                all_repositories=PermissionLevel.PULL,
            ),
        )
        assert policy.github.all_repositories == PermissionLevel.PULL


# --- ConditionalAccessPolicy tests ---


class TestConditionalAccessPolicy:
    def test_ca_policy_mfa_for_admins(self):
        policy = ConditionalAccessPolicy(
            name="Require MFA for Admins",
            state=CAState.ENABLED,
            conditions=CAConditions(
                users=CAConditionUsers(
                    include_groups=["sg-admin"],
                ),
            ),
            grant_controls=CAGrantControls(
                built_in_controls=["mfa"],
            ),
        )
        assert policy.state == CAState.ENABLED
        assert "mfa" in policy.grant_controls.built_in_controls


# --- IAMConfig validation tests ---


class TestIAMConfig:
    def test_valid_config_from_inventory(self):
        config = _minimal_config()
        assert len(config.users) == 5
        assert len(config.groups) == 3

    def test_unknown_group_membership_rejected(self):
        users = _acme_users()
        users["alice"].group_memberships.append("NonExistentGroup")
        with pytest.raises(ValueError, match="unknown group 'NonExistentGroup'"):
            _minimal_config(users=users)

    def test_unknown_member_reference_rejected(self):
        groups = _acme_groups()
        groups["sg-admin"].members.append(MemberReference(name="ghost"))
        with pytest.raises(ValueError, match="unknown principal 'ghost'"):
            _minimal_config(groups=groups)

    def test_circular_nesting_rejected(self):
        groups = {
            "GroupA": SecurityGroup(
                name="GroupA",
                members=[MemberReference(name="GroupB", principal_type=PrincipalType.GROUP)],
            ),
            "GroupB": SecurityGroup(
                name="GroupB",
                members=[MemberReference(name="GroupA", principal_type=PrincipalType.GROUP)],
            ),
        }
        with pytest.raises(ValueError, match="Circular group nesting"):
            IAMConfig(groups=groups)

    def test_license_group_unknown_sku_rejected(self):
        groups = {
            "license-fake-sku": LicenseGroup(
                name="license-fake-sku",
                sku="FAKE_SKU",
            ),
        }
        skus = _acme_license_skus()
        with pytest.raises(ValueError, match="unknown SKU 'FAKE_SKU'"):
            IAMConfig(groups=groups, license_skus=skus)

    def test_license_group_user_missing_location_rejected(self):
        users = {
            "noplace": User(
                name="noplace",
                display_name="No Place",
                email="noplace@acme.example",
                # usage_location intentionally missing
            ),
        }
        groups = {
            "license-o365-business-premium": LicenseGroup(
                name="license-o365-business-premium",
                sku="O365_BUSINESS_PREMIUM",
                members=[MemberReference(name="noplace")],
            ),
        }
        with pytest.raises(ValueError, match="missing required 'usage_location'"):
            IAMConfig(users=users, groups=groups, license_skus=_acme_license_skus())

    def test_duplicate_github_handles_rejected(self):
        users = {
            "user1": User(
                name="user1",
                display_name="User 1",
                email="u1@acme.example",
                platform_config=PlatformConfig(
                    github=GitHubUserConfig(handle="same_handle"),
                ),
            ),
            "user2": User(
                name="user2",
                display_name="User 2",
                email="u2@acme.example",
                platform_config=PlatformConfig(
                    github=GitHubUserConfig(handle="same_handle"),
                ),
            ),
        }
        with pytest.raises(ValueError, match="Duplicate GitHub handle"):
            IAMConfig(users=users)

    def test_manager_self_reference_rejected(self):
        users = {
            "self_managed": User(
                name="self_managed",
                display_name="Self",
                email="self@acme.example",
                manager="self_managed",
            ),
        }
        with pytest.raises(ValueError, match="lists themselves as manager"):
            IAMConfig(users=users)

    def test_manager_unknown_reference_rejected(self):
        users = {
            "orphan": User(
                name="orphan",
                display_name="Orphan",
                email="orphan@acme.example",
                manager="nobody",
            ),
        }
        with pytest.raises(ValueError, match="unknown manager 'nobody'"):
            IAMConfig(users=users)

    def test_ca_policy_unknown_group_rejected(self):
        ca = {
            "test_policy": ConditionalAccessPolicy(
                name="Test",
                conditions=CAConditions(
                    users=CAConditionUsers(include_groups=["NonExistent"]),
                ),
            ),
        }
        with pytest.raises(ValueError, match="unknown group 'NonExistent'"):
            IAMConfig(conditional_access_policies=ca)

    def test_shared_mailbox_unknown_delegate_rejected(self):
        mailboxes = {
            "team": SharedMailbox(
                name="team",
                email_address="team@acme.example",
                display_name="Team",
                delegates=["nobody"],
            ),
        }
        with pytest.raises(ValueError, match="unknown delegate 'nobody'"):
            IAMConfig(shared_mailboxes=mailboxes)

    def test_user_group_name_collision_rejected(self):
        users = {
            "engineering": User(
                name="engineering",
                display_name="Engineering Bot",
                email="engineering@acme.example",
            ),
        }
        groups = {
            "engineering": SecurityGroup(name="engineering"),
        }
        with pytest.raises(ValueError, match="Name 'engineering' is used by both"):
            IAMConfig(users=users, groups=groups)

    def test_user_shared_mailbox_name_collision_rejected(self):
        users = {
            "support": User(
                name="support",
                display_name="Support User",
                email="support-user@acme.example",
            ),
        }
        mailboxes = {
            "support": SharedMailbox(
                name="support",
                email_address="support@acme.example",
                display_name="Support Mailbox",
            ),
        }
        with pytest.raises(ValueError, match="Name 'support' is used by both"):
            IAMConfig(users=users, shared_mailboxes=mailboxes)

    def test_managed_identity_group_member_accepted(self):
        identities = {
            "mi-deployer": ManagedIdentity(
                name="mi-deployer",
                resource_group="rg-infra",
                location="westeurope",
            ),
        }
        groups = {
            "sg-deployers": SecurityGroup(
                name="sg-deployers",
                members=[MemberReference(name="mi-deployer")],
            ),
        }
        config = IAMConfig(managed_identities=identities, groups=groups)
        assert "mi-deployer" in config.managed_identities

    def test_shared_mailbox_group_member_accepted(self):
        mailboxes = {
            "info": SharedMailbox(
                name="info",
                email_address="info@acme.example",
                display_name="Info",
            ),
        }
        groups = {
            "sg-frontdesk": SecurityGroup(
                name="sg-frontdesk",
                members=[MemberReference(name="info")],
            ),
        }
        config = IAMConfig(shared_mailboxes=mailboxes, groups=groups)
        assert "info" in config.shared_mailboxes

    def test_external_users_in_config(self):
        config = _minimal_config(
            external_users={
                "windmill": ExternalUser(
                    email="info@windmill.example",
                    display_name="Windmill Trust",
                ),
            },
        )
        assert "windmill" in config.external_users

    def test_valid_manager_chain(self):
        users = {
            "boss": User(
                name="boss", display_name="Boss", email="boss@acme.example",
            ),
            "report": User(
                name="report", display_name="Report", email="report@acme.example",
                manager="boss",
            ),
        }
        config = IAMConfig(users=users)
        assert config.users["report"].manager == "boss"


class TestStrictParsing:
    def test_license_group_dict_without_type_fails_loudly(self):
        import pytest
        from pydantic import TypeAdapter, ValidationError

        from iamkit.models.groups import Group

        with pytest.raises(ValidationError):
            TypeAdapter(Group).validate_python(
                {"name": "license-e3", "sku": "SPE_E3"}  # no "type" key
            )


class TestAccessPolicyReferences:
    def test_unknown_policy_group_fails_validation(self):
        import pytest
        from pydantic import ValidationError

        from iamkit.models.access import AccessPolicy

        with pytest.raises(ValidationError, match="unknown group 'sg-ghost'"):
            IAMConfig(
                access_policies={
                    "p": AccessPolicy(name="p", group="sg-ghost"),
                }
            )
