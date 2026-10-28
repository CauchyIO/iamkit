"""ACME Corp, platform edition: the whole two-plane model in one fictional tenant.

The minimal example in config.py shows the config pattern. This one adds
everything the access explorer draws: a guest, agent service principals held
in an agent group that people own, environment-scoped groups, a nested group,
declared Applications with workspaces, and access policies that carry each
group onto GitHub, Linear, an Entra role, SharePoint and those applications.
"""

from iamkit.models.access import (
    AccessPolicy,
    AppAccessSpec,
    Application,
    AzureRoleAssignment,
    GitHubAccessSpec,
    LinearAccessSpec,
    SharePointAccessSpec,
)
from iamkit.models.base import MemberReference
from iamkit.models.config import IAMConfig
from iamkit.models.enums import (
    Environment,
    GitHubOrgRole,
    LinearRole,
    PermissionLevel,
    PrincipalType,
)
from iamkit.models.groups import LicenseGroup, M365Group, MailingList, SecurityGroup
from iamkit.models.license import LicenseSKU
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


def _user(ref: str) -> MemberReference:
    return MemberReference(name=ref)


def build_acme_platform_config() -> IAMConfig:
    users = {
        "alice": User(
            name="alice",
            display_name="Alice Anvil",
            email="alice@acme.example",
            department="Engineering",
            job_title="Engineering lead",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="alice-acme", org_role=GitHubOrgRole.ADMIN),
                linear=LinearUserConfig(email="alice@acme.example", role=LinearRole.ADMIN),
            ),
            group_memberships=["sg-engineering", "sg-platform-admins"],
        ),
        "bob": User(
            name="bob",
            display_name="Bob Beaker",
            email="bob@acme.example",
            department="Engineering",
            manager="alice",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="bob-acme"),
                linear=LinearUserConfig(email="bob@acme.example"),
            ),
            group_memberships=["sg-engineering"],
        ),
        "carol": User(
            name="carol",
            display_name="Carol Crane",
            email="carol@acme.example",
            department="Platform",
            job_title="Platform engineer",
            manager="alice",
            usage_location="NL",
            platform_config=PlatformConfig(
                github=GitHubUserConfig(handle="carol-acme"),
                linear=LinearUserConfig(email="carol@acme.example"),
            ),
            group_memberships=["sg-engineering", "sg-platform-admins", "sg-portal-prd"],
        ),
        "dave": User(
            name="dave",
            display_name="Dave Dynamo",
            email="dave@acme.example",
            usage_location="NL",
            account_enabled=False,
            platform_config=PlatformConfig(github=GitHubUserConfig(handle="dave-acme")),
            group_memberships=["sg-engineering"],
        ),
        "erin": User(
            name="erin",
            display_name="Erin Echo",
            email="erin@acme.example",
            job_title="Break-glass administrator",
            managed=False,
        ),
    }
    external_users = {
        "frank": ExternalUser(
            email="frank@partner.example",
            display_name="Frank Fuse (Partner)",
            send_invitation=False,
            group_memberships=["sg-portal-prd"],
        ),
    }
    service_principals = {
        "builder-agent": ServicePrincipal(
            name="builder-agent",
            display_name="Builder agent",
            group_memberships=["sg-agents"],
        ),
        "reviewer-agent": ServicePrincipal(
            name="reviewer-agent",
            display_name="Reviewer agent",
            group_memberships=["sg-agents"],
        ),
    }
    managed_identities = {
        "deploy-identity": ManagedIdentity(
            name="deploy-identity",
            resource_group="rg-acme-platform",
            location="westeurope",
        ),
    }
    shared_mailboxes = {
        "support": SharedMailbox(
            name="support",
            email_address="support@acme.example",
            display_name="ACME Support",
            delegates=["carol"],
        ),
    }

    groups = {
        "sg-engineering": SecurityGroup(
            name="sg-engineering",
            display_name="Engineering",
            description="Everyone who builds ACME software",
            members=[_user("alice"), _user("bob"), _user("carol"), _user("dave")],
            owners=[_user("alice")],
        ),
        "sg-platform-admins": SecurityGroup(
            name="sg-platform-admins",
            display_name="Platform admins",
            description="Operate the ACME platform and its agents",
            members=[_user("alice"), _user("carol")],
            owners=[_user("alice")],
            assignable_to_role=True,
        ),
        # Agents are service principals, so their group is answered for by
        # the people who own it.
        "sg-agents": SecurityGroup(
            name="sg-agents",
            display_name="Platform agents",
            description="Non-human workers on the agent runtime",
            members=[
                MemberReference(name="builder-agent", principal_type=PrincipalType.SERVICE_PRINCIPAL),
                MemberReference(name="reviewer-agent", principal_type=PrincipalType.SERVICE_PRINCIPAL),
                MemberReference(name="deploy-identity", principal_type=PrincipalType.MANAGED_IDENTITY),
            ],
            owners=[_user("alice"), _user("carol")],
        ),
        # One group shell per environment: engineering builds in DEV through
        # nesting, and production is held by named people and a partner guest.
        "sg-portal-dev": SecurityGroup(
            name="sg-portal",
            display_name="Portal (DEV)",
            environment=Environment.DEV,
            members=[MemberReference(name="sg-engineering", principal_type=PrincipalType.GROUP)],
            owners=[_user("alice")],
        ),
        "sg-portal-prd": SecurityGroup(
            name="sg-portal",
            display_name="Portal (PRD)",
            environment=Environment.PRD,
            members=[
                _user("carol"),
                MemberReference(name="frank", principal_type=PrincipalType.EXTERNAL_USER),
            ],
            owners=[_user("alice"), _user("carol")],
        ),
        "license-e3": LicenseGroup(
            name="license-e3",
            display_name="License: E3",
            sku="SPE_E3",
            members=[_user("alice"), _user("bob"), _user("carol")],
            owners=[_user("alice")],
        ),
        "m365-support": M365Group(
            name="m365-support",
            display_name="Support team",
            members=[_user("bob"), _user("carol")],
            owners=[_user("carol")],
        ),
        "ml-announcements": MailingList(
            name="ml-announcements",
            display_name="Announcements",
            email_address="announcements@acme.example",
            members=[_user("alice"), _user("bob"), _user("carol")],
        ),
    }

    applications = {
        "acme-portal": Application(
            name="acme-portal",
            display_name="ACME Portal",
            workspaces=["acme", "acme-labs"],
        ),
        "agent-runtime": Application(
            name="agent-runtime",
            display_name="Agent runtime",
            available_roles=["admin", "member"],
            available_scopes=["runs.cancel", "runs.read", "runs.submit"],
            workspaces=["acme", "acme-labs"],
        ),
    }

    access_policies = {
        "engineering-access": AccessPolicy(
            name="engineering-access",
            group="sg-engineering",
            description="Build and ship ACME software",
            github=GitHubAccessSpec(
                team_name="engineering",
                all_repositories=PermissionLevel.PUSH,
                exclude_repositories=["infra-secrets"],
                repositories={"widget-factory": PermissionLevel.MAINTAIN},
                external_members=["zed-contractor"],
            ),
            linear=LinearAccessSpec(teams=["ENG"]),
            applications=[AppAccessSpec(application="acme-portal", role="member", workspaces=["acme"])],
        ),
        "platform-admin-access": AccessPolicy(
            name="platform-admin-access",
            group="sg-platform-admins",
            description="Administer the platform, its directory groups and its agents",
            entra_roles=["Groups Administrator"],
            github=GitHubAccessSpec(
                team_name="platform",
                repositories={"infra-secrets": PermissionLevel.ADMIN},
            ),
            applications=[
                AppAccessSpec(application="acme-portal", role="admin", workspaces=["acme", "acme-labs"]),
                AppAccessSpec(
                    application="agent-runtime",
                    role="admin",
                    workspaces=["acme", "acme-labs"],
                    scopes=["runs.cancel", "runs.read", "runs.submit"],
                ),
            ],
        ),
        "agent-access": AccessPolicy(
            name="agent-access",
            group="sg-agents",
            description="Agents run work in the labs workspace only",
            applications=[
                AppAccessSpec(
                    application="agent-runtime",
                    role="member",
                    workspaces=["acme-labs"],
                    scopes=["runs.read", "runs.submit"],
                ),
            ],
        ),
        "portal-dev-access": AccessPolicy(
            name="portal-dev-access",
            group="sg-portal-dev",
            description="Administer the portal's labs workspace in DEV",
            applications=[AppAccessSpec(application="acme-portal", role="admin", workspaces=["acme-labs"])],
        ),
        "portal-prd-access": AccessPolicy(
            name="portal-prd-access",
            group="sg-portal-prd",
            description="Read the production portal",
            sharepoint=SharePointAccessSpec(sites={"Portal handbook": PermissionLevel.READ}),
            applications=[AppAccessSpec(application="acme-portal", role="reader", workspaces=["acme"])],
        ),
        "support-access": AccessPolicy(
            name="support-access",
            group="m365-support",
            description="Edit the support knowledge base",
            sharepoint=SharePointAccessSpec(sites={"Support": PermissionLevel.CONTRIBUTE}),
        ),
    }

    return IAMConfig(
        users=users,
        external_users=external_users,
        service_principals=service_principals,
        managed_identities=managed_identities,
        shared_mailboxes=shared_mailboxes,
        groups=groups,
        applications=applications,
        access_policies=access_policies,
        azure_role_assignments=[
            AzureRoleAssignment(
                group_name="sg-platform-admins",
                role="Contributor",
                scope="/subscriptions/acme-platform/resourceGroups/rg-acme-platform",
            ),
            # Assignments name the group as Entra knows it, environment suffix included.
            AzureRoleAssignment(
                group_name="sg-portal_prd",
                role="Reader",
                scope="/subscriptions/acme-production",
            ),
        ],
        license_skus={
            "SPE_E3": LicenseSKU(
                sku_id="05e9a617-0261-4cee-bb44-138d3ef5d965",
                sku_part_number="SPE_E3",
                friendly_name="Microsoft 365 E3",
            ),
        },
    )
