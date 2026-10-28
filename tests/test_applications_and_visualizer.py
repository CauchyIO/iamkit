"""Applications, their group-held grants, and the access explorer.

No mocks: every config is a real IAMConfig (the ACME platform showcase or a
small inline one), the GitHub and Linear rows are checked against the real
exporter and executor, the explorer is checked as the bytes it ships, and the
browser tests render it in a real headless Chrome when one is installed.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))  # make `examples` importable

import iamkit
from examples.acme.platform import build_acme_platform_config
from examples.acme.visualize import OUTPUT as COMMITTED_EXPLORER
from examples.acme.visualize import TITLE as ACME_TITLE
from iamkit.executors.linear import resolve_desired_state
from iamkit.export import build_access_graph, export_application_grants, generate_visualizer_html
from iamkit.export.terraform import TerraformExporter
from iamkit.models import AppAccessSpec, Application
from iamkit.models.access import AccessPolicy, AzureRoleAssignment, GitHubAccessSpec
from iamkit.models.base import MemberReference
from iamkit.models.config import IAMConfig
from iamkit.models.enums import Environment, PrincipalSource, PrincipalType
from iamkit.models.groups import M365Group, SecurityGroup
from iamkit.models.principals import (
    ExternalUser,
    GitHubUserConfig,
    PlatformConfig,
    ServicePrincipal,
    User,
)

# -- builders ------------------------------------------------------------------


def _ref(name: str, kind: PrincipalType = PrincipalType.USER) -> MemberReference:
    return MemberReference(name=name, principal_type=kind)


def _person(name: str, **fields) -> User:
    return User(name=name, display_name=name.title(), email=f"{name}@acme.example", **fields)


def _portal(**fields) -> Application:
    values = {
        "name": "portal",
        "display_name": "Portal",
        "available_scopes": ["read", "write"],
        "workspaces": ["north", "south"],
    }
    values.update(fields)
    return Application(**values)


def _config(*, users=None, groups=None, applications=None, policies=None, **extra) -> IAMConfig:
    """A valid one-group, one-binding config unless a section is overridden."""
    return IAMConfig(
        users=users if users is not None else {"ann": _person("ann"), "ben": _person("ben")},
        groups=groups
        if groups is not None
        else {
            "sg-team": SecurityGroup(
                name="sg-team", members=[_ref("ann"), _ref("ben")], owners=[_ref("ann")]
            )
        },
        applications=applications if applications is not None else {"portal": _portal()},
        access_policies=policies
        if policies is not None
        else {
            "team-access": AccessPolicy(
                name="team-access",
                group="sg-team",
                applications=[AppAccessSpec(application="portal", role="member", workspaces=["north"])],
            )
        },
        **extra,
    )


def _binding(**fields) -> dict[str, AccessPolicy]:
    spec = {"application": "portal", "role": "member", "workspaces": ["north"]}
    spec.update(fields)
    return {
        "team-access": AccessPolicy(
            name="team-access", group="sg-team", applications=[AppAccessSpec(**spec)]
        )
    }


def _errors(**sections) -> str:
    with pytest.raises(ValidationError) as info:
        _config(**sections)
    return str(info.value)


def _reversed(config: IAMConfig) -> IAMConfig:
    """The same config declared back to front: every mapping and order-free list flipped."""

    def flip(mapping: dict) -> dict:
        return dict(reversed(list(mapping.items())))

    groups = {}
    for key, group in reversed(list(config.groups.items())):
        update = {"members": list(reversed(group.members))}
        if hasattr(group, "owners"):
            update["owners"] = list(reversed(group.owners))
        groups[key] = group.model_copy(update=update)
    applications = {
        key: app.model_copy(
            update={
                "workspaces": list(reversed(app.workspaces)),
                "available_scopes": list(reversed(app.available_scopes)),
                "redirect_uris": list(reversed(app.redirect_uris)),
            }
        )
        for key, app in reversed(list(config.applications.items()))
    }
    policies = {}
    for key, policy in reversed(list(config.access_policies.items())):
        update = {
            "entra_roles": list(reversed(policy.entra_roles)),
            "applications": [
                spec.model_copy(
                    update={
                        "workspaces": list(reversed(spec.workspaces)),
                        "scopes": list(reversed(spec.scopes)),
                    }
                )
                for spec in reversed(policy.applications)
            ],
        }
        if policy.github is not None:
            update["github"] = policy.github.model_copy(
                update={"external_members": list(reversed(policy.github.external_members))}
            )
        policies[key] = policy.model_copy(update=update)
    return IAMConfig(
        users=flip(config.users),
        external_users=flip(config.external_users),
        service_principals=flip(config.service_principals),
        managed_identities=flip(config.managed_identities),
        shared_mailboxes=flip(config.shared_mailboxes),
        groups=groups,
        applications=applications,
        access_policies=policies,
        azure_role_assignments=list(reversed(config.azure_role_assignments)),
        license_skus=flip(config.license_skus),
    )


@pytest.fixture(scope="module")
def acme() -> IAMConfig:
    return build_acme_platform_config()


@pytest.fixture(scope="module")
def graph(acme: IAMConfig) -> dict:
    return build_access_graph(acme)


# -- models ----------------------------------------------------------------------


class TestApplicationModel:
    def test_defaults(self):
        app = Application(name="portal", display_name="Portal")
        assert app.source == PrincipalSource.ENTRA
        assert app.available_roles == ["admin", "member", "reader"]
        assert (app.application_id, app.audience) == (None, None)
        assert app.redirect_uris == app.available_scopes == app.workspaces == []

    def test_rejects_unknown_fields(self):
        with pytest.raises(ValidationError, match="extra"):
            Application(name="portal", display_name="Portal", owner="ann")
        with pytest.raises(ValidationError, match="extra"):
            AppAccessSpec(application="portal", role="member", expires="never")

    @pytest.mark.parametrize("field", ["redirect_uris", "available_roles", "available_scopes", "workspaces"])
    def test_application_rejects_duplicate_entries(self, field):
        with pytest.raises(ValidationError, match=f"Duplicate {field}: x"):
            Application(name="portal", display_name="Portal", **{field: ["x", "y", "x"]})

    @pytest.mark.parametrize("field", ["workspaces", "scopes"])
    def test_binding_rejects_duplicate_entries(self, field):
        with pytest.raises(ValidationError, match=f"Duplicate {field}: x"):
            AppAccessSpec(application="portal", role="member", **{field: ["x", "x"]})

    def test_policies_without_bindings_are_unchanged(self):
        assert AccessPolicy(name="p", group="g").applications == []
        assert IAMConfig().applications == {}

    def test_public_exports(self):
        assert iamkit.Application is Application
        assert iamkit.AppAccessSpec is AppAccessSpec
        assert {"Application", "AppAccessSpec"} <= set(iamkit.__all__)


# -- validation ------------------------------------------------------------------


class TestApplicationValidation:
    def test_valid_binding_passes(self):
        assert _config().access_policies["team-access"].applications[0].role == "member"

    def test_acme_platform_config_validates(self, acme):
        assert set(acme.applications) == {"acme-portal", "agent-runtime"}

    def test_unknown_application(self):
        message = _errors(policies=_binding(application="ghost"))
        assert "AccessPolicy 'team-access' references unknown application 'ghost'" in message

    def test_key_must_match_name(self):
        message = _errors(applications={"portal": _portal(), "intranet": _portal()})
        assert "Application key 'intranet' does not match its name 'portal'" in message

    def test_binding_needs_a_group(self):
        policies = {
            "loose": AccessPolicy(
                name="loose",
                applications=[AppAccessSpec(application="portal", role="member", workspaces=["north"])],
            )
        }
        assert "AccessPolicy 'loose' binds applications but names no group" in _errors(policies=policies)

    def test_binding_group_must_be_a_security_group(self):
        groups = {"sg-team": M365Group(name="sg-team", members=[_ref("ann")], owners=[_ref("ann")])}
        message = _errors(groups=groups)
        assert "binds applications through 'sg-team', which is not a security group" in message

    @pytest.mark.parametrize(
        "owners",
        [
            pytest.param([], id="no-owner"),
            pytest.param([_ref("robot", PrincipalType.SERVICE_PRINCIPAL)], id="only-a-service-principal"),
            pytest.param([_ref("gone")], id="only-a-disabled-user"),
        ],
    )
    def test_binding_group_needs_an_enabled_human_owner(self, owners):
        message = _errors(
            users={"ann": _person("ann"), "gone": _person("gone", account_enabled=False)},
            groups={"sg-team": SecurityGroup(name="sg-team", members=[_ref("ann")], owners=owners)},
            service_principals={"robot": ServicePrincipal(name="robot")},
        )
        assert "through group 'sg-team', which has no enabled human owner" in message

    def test_a_guest_owner_answers_for_the_group(self):
        config = _config(
            external_users={"gus": ExternalUser(email="gus@partner.example", display_name="Gus")},
            groups={
                "sg-team": SecurityGroup(
                    name="sg-team",
                    members=[_ref("ann")],
                    owners=[_ref("gus", PrincipalType.EXTERNAL_USER)],
                )
            },
        )
        assert config.groups["sg-team"].owners[0].name == "gus"

    def test_unknown_role_lists_the_available_ones(self):
        message = _errors(policies=_binding(role="owner"))
        assert "uses unknown role 'owner' (available: admin, member, reader)" in message

    def test_undeclared_scope(self):
        message = _errors(policies=_binding(scopes=["read", "delete"]))
        assert "requests undeclared scope(s) delete (available: read, write)" in message

    def test_undeclared_workspace(self):
        message = _errors(policies=_binding(workspaces=["north", "west"]))
        assert "names undeclared workspace(s) west (available: north, south)" in message

    def test_partitioned_application_needs_named_workspaces(self):
        message = _errors(policies=_binding(workspaces=[]))
        assert "names no workspace; the application is partitioned into north, south" in message

    def test_unpartitioned_application_takes_no_workspaces(self):
        config = _config(applications={"portal": _portal(workspaces=[])}, policies=_binding(workspaces=[]))
        assert config.access_policies["team-access"].applications[0].workspaces == []

    def test_errors_are_reported_together(self):
        policies = {
            "a-access": AccessPolicy(
                name="a-access",
                group="sg-team",
                applications=[AppAccessSpec(application="ghost", role="member")],
            ),
            "b-access": AccessPolicy(
                name="b-access",
                group="sg-team",
                applications=[
                    AppAccessSpec(application="portal", role="owner", workspaces=["north"], scopes=["delete"])
                ],
            ),
        }
        message = _errors(policies=policies)
        assert "IAMConfig validation failed with 3 error(s)" in message
        assert "unknown application 'ghost'" in message
        assert "unknown role 'owner'" in message
        assert "undeclared scope(s) delete" in message


# -- application grants ------------------------------------------------------------


class TestApplicationGrantsExport:
    def test_applications_section(self, acme):
        applications = export_application_grants(acme)["applications"]
        assert list(applications) == ["acme-portal", "agent-runtime"]
        assert applications["agent-runtime"] == {
            "name": "agent-runtime",
            "display_name": "Agent runtime",
            "source": "entra",
            "application_id": None,
            "audience": None,
            "redirect_uris": [],
            "available_roles": ["admin", "member"],
            "available_scopes": ["runs.cancel", "runs.read", "runs.submit"],
            "workspaces": ["acme", "acme-labs"],
        }

    def test_declared_role_order_is_kept(self):
        config = _config(applications={"portal": _portal(available_roles=["viewer", "editor", "admin"])}, policies={})
        assert export_application_grants(config)["applications"]["portal"]["available_roles"] == [
            "viewer",
            "editor",
            "admin",
        ]

    def test_workspace_grants_by_group(self, acme):
        grants = export_application_grants(acme)["workspace_grants"]
        assert list(grants) == [
            "sg-agents",
            "sg-engineering",
            "sg-platform-admins",
            "sg-portal-dev",
            "sg-portal-prd",
        ]
        assert grants["sg-portal-dev"] == {
            "resolved_name": "sg-portal_dev",
            "display_name": "Portal (DEV)",
            "environment": "dev",
            "members": [{"name": "sg-engineering", "principal_type": "group"}],
            "owners": [{"name": "alice", "principal_type": "user"}],
            "grants": [
                {
                    "application": "acme-portal",
                    "role": "admin",
                    "workspaces": ["acme-labs"],
                    "scopes": [],
                    "policy": "portal-dev-access",
                }
            ],
        }
        assert grants["sg-agents"]["members"] == [
            {"name": "builder-agent", "principal_type": "service_principal"},
            {"name": "deploy-identity", "principal_type": "managed_identity"},
            {"name": "reviewer-agent", "principal_type": "service_principal"},
        ]
        assert [(g["application"], g["role"]) for g in grants["sg-platform-admins"]["grants"]] == [
            ("acme-portal", "admin"),
            ("agent-runtime", "admin"),
        ]

    def test_groups_without_bindings_are_left_out(self, acme):
        grants = export_application_grants(acme)["workspace_grants"]
        assert not {"license-e3", "m365-support", "ml-announcements"} & set(grants)

    def test_grants_from_several_policies_merge_under_their_group(self):
        policies = {
            "z-access": AccessPolicy(
                name="z-access",
                group="sg-team",
                applications=[AppAccessSpec(application="portal", role="admin", workspaces=["south"])],
            ),
            "a-access": AccessPolicy(
                name="a-access",
                group="sg-team",
                applications=[AppAccessSpec(application="portal", role="admin", workspaces=["north"])],
            ),
        }
        grants = export_application_grants(_config(policies=policies))["workspace_grants"]["sg-team"]["grants"]
        assert [(g["policy"], g["workspaces"]) for g in grants] == [
            ("a-access", ["north"]),
            ("z-access", ["south"]),
        ]

    def test_independent_of_declaration_order(self, acme):
        forward = json.dumps(export_application_grants(acme))
        assert json.dumps(export_application_grants(_reversed(acme))) == forward

    def test_terraform_inputs_are_unchanged_by_applications(self, acme):
        bare = acme.model_copy(
            update={
                "applications": {},
                "access_policies": {
                    key: policy.model_copy(update={"applications": []})
                    for key, policy in acme.access_policies.items()
                },
            }
        )
        with_apps = TerraformExporter(acme, github_org_default="acme-corp")
        without = TerraformExporter(bare, github_org_default="acme-corp")
        assert with_apps.export_entra_tfvars() == without.export_entra_tfvars()
        assert with_apps.export_github_tfvars() == without.export_github_tfvars()


# -- the access graph ----------------------------------------------------------------


def _node(graph: dict, node_id: str) -> dict:
    return next(n for n in graph["nodes"] if n["id"] == node_id)


def _edges(graph: dict, kind: str) -> set[tuple[str, str]]:
    return {(e["source"], e["target"]) for e in graph["edges"] if e["kind"] == kind}


class TestAccessGraph:
    def test_every_kind_of_node(self, graph):
        kinds = {n["id"]: n["kind"] for n in graph["nodes"]}
        assert {
            "user:alice": "user",
            "guest:frank": "external_user",
            "handle:zed-contractor": "github_handle",
            "sp:builder-agent": "service_principal",
            "mi:deploy-identity": "managed_identity",
            "mailbox:support": "shared_mailbox",
            "group:sg-engineering": "security_group",
            "group:license-e3": "license_group",
            "group:m365-support": "m365_group",
            "group:ml-announcements": "mailing_list",
            "policy:engineering-access": "policy",
            "github:engineering": "github_team",
            "linear": "linear",
            "entra:Groups Administrator": "entra_role",
            "rbac:Reader@/subscriptions/acme-production": "azure_rbac",
            "sharepoint:Support": "sharepoint_site",
            "app:agent-runtime": "application",
            "workspace:acme-labs": "workspace",
        }.items() <= kinds.items()

    def test_edges_and_rows_only_reference_nodes(self, graph):
        ids = {n["id"] for n in graph["nodes"]}
        for edge in graph["edges"]:
            assert {edge["source"], edge["target"]} <= ids, edge
        for row in graph["rows"]:
            assert {row["principal"], row["target"], *row["via"]} <= ids, row
            assert row["policy"] is None or row["policy"] in ids, row

    def test_environment_scoped_groups(self, graph):
        assert _node(graph, "group:sg-portal-dev")["env"] == "dev"
        assert _node(graph, "group:sg-portal-prd")["env"] == "prd"
        assert _node(graph, "group:sg-engineering")["env"] is None
        assert graph["environments"] == ["dev", "acc", "prd"]
        assert graph["defaultEnvironment"] == "prd"

    def test_agent_group(self, graph):
        agents = _node(graph, "group:sg-agents")
        assert agents["agent"] is True
        assert {"tone": "info", "text": "Agent group: non-human members, answered for by its owners (IAM-P06)"} in agents["badges"]
        assert _node(graph, "group:sg-engineering")["agent"] is False

    def test_plane_one_edges(self, graph):
        assert ("user:dave", "group:sg-engineering") in _edges(graph, "member")
        assert ("group:sg-engineering", "group:sg-portal-dev") in _edges(graph, "member")
        assert ("guest:frank", "group:sg-portal-prd") in _edges(graph, "member")
        assert ("user:carol", "group:sg-agents") in _edges(graph, "owner")

    def test_plane_two_edges(self, graph):
        assert ("group:sg-engineering", "policy:engineering-access") in _edges(graph, "policy")
        assert ("handle:zed-contractor", "policy:engineering-access") in _edges(graph, "external_member")
        assert ("app:acme-portal", "workspace:acme-labs") in _edges(graph, "workspace")
        assert ("group:sg-platform-admins", "rbac:Contributor@/subscriptions/acme-platform/resourceGroups/rg-acme-platform") in _edges(graph, "rbac")
        # Role assignments name the group as Entra knows it, suffix included.
        assert ("group:sg-portal-prd", "rbac:Reader@/subscriptions/acme-production") in _edges(graph, "rbac")

    def test_grant_edges_carry_the_binding(self, graph):
        [edge] = [
            e
            for e in graph["edges"]
            if e["kind"] == "grant" and (e["source"], e["target"]) == ("policy:agent-access", "app:agent-runtime")
        ]
        assert (edge["role"], edge["workspaces"], edge["scopes"]) == (
            "member",
            ["acme-labs"],
            ["runs.read", "runs.submit"],
        )

    def test_governance_badges(self):
        config = IAMConfig(
            users={
                "ann": _person("ann"),
                "old": _person("old", account_enabled=False),
                "root": _person("root", managed=False),
            },
            service_principals={"robot": ServicePrincipal(name="robot")},
            groups={
                "sg-orphan": SecurityGroup(name="sg-orphan", members=[_ref("ann")]),
                "sg-bots": SecurityGroup(
                    name="sg-bots",
                    members=[_ref("robot", PrincipalType.SERVICE_PRINCIPAL)],
                    owners=[_ref("robot", PrincipalType.SERVICE_PRINCIPAL)],
                ),
                "sg-empty": SecurityGroup(name="sg-empty", owners=[_ref("ann")]),
            },
        )
        graph = build_access_graph(config)
        tones = {n["id"]: {b["tone"] for b in n["badges"]} for n in graph["nodes"]}
        assert "critical" in tones["group:sg-orphan"]
        assert "warning" in tones["group:sg-bots"]
        assert _node(graph, "group:sg-bots")["agent"] is True
        assert {"tone": "info", "text": "No members"} in _node(graph, "group:sg-empty")["badges"]
        assert "warning" in tones["user:old"]
        assert "info" in tones["user:root"]

    def test_unresolved_references_are_drawn_not_dropped(self):
        config = _config(
            groups={
                "sg-team": SecurityGroup(
                    name="sg-team", members=[_ref("ann")], owners=[_ref("ann"), _ref("nobody")]
                )
            },
            azure_role_assignments=[AzureRoleAssignment(group_name="sg-ghost", role="Reader", scope="/subscriptions/x")],
        )
        graph = build_access_graph(config)
        for name in ("nobody", "sg-ghost"):
            node = _node(graph, f"unresolved:{name}")
            assert node["kind"] == "unresolved"
            assert node["badges"][0]["tone"] == "critical"
        assert ("unresolved:nobody", "group:sg-team") in _edges(graph, "owner")
        assert ("unresolved:sg-ghost", "rbac:Reader@/subscriptions/x") in _edges(graph, "rbac")

    def test_external_handle_of_a_directory_user_links_that_user(self):
        config = _config(
            users={
                "ann": _person("ann"),
                "ben": _person("ben", platform_config=PlatformConfig(github=GitHubUserConfig(handle="ben-gh"))),
            },
            policies={
                "team-access": AccessPolicy(
                    name="team-access",
                    group="sg-team",
                    github=GitHubAccessSpec(team_name="team", external_members=["ben-gh"]),
                )
            },
        )
        graph = build_access_graph(config)
        assert ("user:ben", "policy:team-access") in _edges(graph, "external_member")
        assert not any(n["kind"] == "github_handle" for n in graph["nodes"])

    def test_independent_of_declaration_order(self, acme, graph):
        assert json.dumps(build_access_graph(_reversed(acme))) == json.dumps(graph)


class TestEffectiveAccess:
    def test_github_rows_match_the_exporter(self, acme, graph):
        handle_of = {f"user:{key}": u.platform_config.github.handle for key, u in acme.users.items() if u.platform_config.github}
        handle_of.update({n["id"]: n["name"] for n in graph["nodes"] if n["kind"] == "github_handle"})
        teams = TerraformExporter(acme).export_github_tfvars()["github_teams"]
        assert teams
        for team in teams:
            rows = {handle_of[r["principal"]] for r in graph["rows"] if r["target"] == f"github:{team['name']}"}
            assert rows == set(team["members"]), team["name"]

    def test_linear_rows_match_the_executor(self, acme, graph):
        email_of = {f"user:{key}": u.platform_config.linear.email for key, u in acme.users.items() if u.platform_config.linear}
        holders = {email_of[r["principal"]] for r in graph["rows"] if r["target"] == "linear"}
        assert holders == {state.email for state in resolve_desired_state(acme)}
        assert holders == {"alice@acme.example", "bob@acme.example", "carol@acme.example"}
        alice_grants = {r["grant"] for r in graph["rows"] if r["principal"] == "user:alice" and r["target"] == "linear"}
        assert all(g.startswith("admin") for g in alice_grants)

    def test_nested_paths_preserve_distinct_environments(self):
        app = Application(name="portal", display_name="Portal", workspaces=["core"])
        config = IAMConfig(
            users={"ann": _person("ann")},
            groups={
                "sg-a-dev": SecurityGroup(
                    name="sg-a-dev", environment=Environment.DEV, members=[_ref("ann")], owners=[_ref("ann")]
                ),
                "sg-b-prd": SecurityGroup(
                    name="sg-b-prd", environment=Environment.PRD, members=[_ref("ann")], owners=[_ref("ann")]
                ),
                "sg-shared": SecurityGroup(
                    name="sg-shared",
                    members=[
                        MemberReference(name="sg-a-dev", principal_type=PrincipalType.GROUP),
                        MemberReference(name="sg-b-prd", principal_type=PrincipalType.GROUP),
                    ],
                    owners=[_ref("ann")],
                ),
            },
            applications={"portal": app},
            access_policies={
                "shared-access": AccessPolicy(
                    name="shared-access",
                    group="sg-shared",
                    applications=[AppAccessSpec(application="portal", role="member", workspaces=["core"])],
                )
            },
        )
        rows = [r for r in build_access_graph(config)["rows"] if r["principal"] == "user:ann" and r["target"] == "app:portal"]
        assert {tuple(r["envs"]) for r in rows} == {("dev",), ("prd",)}

    def test_same_role_bindings_with_different_workspaces_sort_deterministically(self):
        app = Application(name="portal", display_name="Portal", workspaces=["north", "south"])
        spec_a = AppAccessSpec(application="portal", role="member", workspaces=["north"])
        spec_b = AppAccessSpec(application="portal", role="member", workspaces=["south"])
        c1 = _config(
            applications={"portal": app},
            policies={"p": AccessPolicy(name="p", group="sg-team", applications=[spec_a, spec_b])},
        )
        c2 = _config(
            applications={"portal": app},
            policies={"p": AccessPolicy(name="p", group="sg-team", applications=[spec_b, spec_a])},
        )
        assert generate_visualizer_html(c1) == generate_visualizer_html(c2)

    def test_nested_membership_reaches_the_dev_workspace(self, graph):
        rows = [r for r in graph["rows"] if r["principal"] == "user:bob" and r["target"] == "app:acme-portal"]
        assert {
            "principal": "user:bob",
            "target": "app:acme-portal",
            "grant": "admin",
            "via": ["group:sg-engineering", "group:sg-portal-dev"],
            "policy": "policy:portal-dev-access",
            "workspaces": ["acme-labs"],
            "scopes": [],
            "envs": ["dev"],
        } in rows
        assert {(r["grant"], tuple(r["envs"])) for r in rows} == {("admin", ("dev",)), ("member", ())}

    def test_agents_hold_scoped_runtime_access(self, graph):
        rows = [r for r in graph["rows"] if r["target"] == "app:agent-runtime" and r["policy"] == "policy:agent-access"]
        assert {r["principal"] for r in rows} == {"sp:builder-agent", "sp:reviewer-agent", "mi:deploy-identity"}
        assert all(r["workspaces"] == ["acme-labs"] and r["scopes"] == ["runs.read", "runs.submit"] for r in rows)

    def test_a_disabled_account_keeps_its_edges_but_holds_no_rows(self, graph):
        assert ("user:dave", "group:sg-engineering") in _edges(graph, "member")
        assert not [r for r in graph["rows"] if r["principal"] == "user:dave"]

    def test_guest_access_follows_its_environment(self, graph):
        rows = [r for r in graph["rows"] if r["principal"] == "guest:frank"]
        assert {(r["target"], r["grant"]) for r in rows} == {
            ("app:acme-portal", "reader"),
            ("sharepoint:Portal handbook", "read"),
            ("rbac:Reader@/subscriptions/acme-production", "Reader @ /subscriptions/acme-production"),
        }
        assert all(r["envs"] == ["prd"] for r in rows)

    def test_external_handles_follow_their_policys_environment(self):
        config = IAMConfig(
            users={"ann": _person("ann")},
            groups={
                "sg-labs": SecurityGroup(
                    name="sg-labs", environment=Environment.DEV, members=[_ref("ann")], owners=[_ref("ann")]
                )
            },
            access_policies={
                "labs-access": AccessPolicy(
                    name="labs-access",
                    group="sg-labs",
                    github=GitHubAccessSpec(team_name="labs", external_members=["outsider"]),
                )
            },
        )
        [row] = build_access_graph(config)["rows"]
        assert (row["principal"], row["envs"]) == ("handle:outsider", ["dev"])

    def test_role_assignments_reach_members(self, graph):
        assert {
            "principal": "user:alice",
            "target": "rbac:Contributor@/subscriptions/acme-platform/resourceGroups/rg-acme-platform",
            "grant": "Contributor @ /subscriptions/acme-platform/resourceGroups/rg-acme-platform",
            "via": ["group:sg-platform-admins"],
            "policy": None,
            "workspaces": [],
            "scopes": [],
            "envs": [],
        } in graph["rows"]


# -- the explorer page ------------------------------------------------------------------

DATA_OPEN = '<script type="application/json" id="iam-data">'
HOSTILE = '</script><script>alert(1)</script><!-- <img src=x onerror=alert(2)> __IAMKIT_SCRIPT__ &amp;'
HOSTILE_TITLE = "<b>Owned</b> & co"


def _between(text: str, start: str, end: str) -> str:
    begin = text.index(start) + len(start)
    return text[begin : text.index(end, begin)]


def _parts(page: str) -> dict[str, str]:
    return {
        "csp": _between(page, '<meta http-equiv="Content-Security-Policy" content="', '">'),
        "style": _between(page, "<style>", "</style>"),
        "data": _between(page, DATA_OPEN, "</script>"),
        "script": _between(page, "<script>", "</script>"),
    }


def _hash_source(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode() + "'"


def _asset(name: str) -> str:
    return files("iamkit.export").joinpath("explorer").joinpath(name).read_text(encoding="utf-8")


def _hostile_config() -> IAMConfig:
    return IAMConfig(
        users={"ann": User(name="ann", display_name=HOSTILE, email="ann@acme.example")},
        groups={
            "sg-x": SecurityGroup(
                name="sg-x", description="</style><style>*{}", members=[_ref("ann")], owners=[_ref("ann")]
            )
        },
        access_policies={"x-access": AccessPolicy(name="x-access", group="sg-x", description=HOSTILE)},
    )


@pytest.fixture(scope="module")
def page(acme: IAMConfig) -> str:
    return generate_visualizer_html(acme, title=ACME_TITLE)


class TestExplorerPage:
    def test_full_document_skeleton(self, page):
        assert page.startswith("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">")
        assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page
        assert f"<title>{ACME_TITLE}</title>" in page
        assert "<body>" in page and page.rstrip().endswith("</body>\n</html>")

    def test_csp_blocks_everything_but_the_pinned_inline_assets(self, page):
        parts = _parts(page)
        assert parts["csp"] == "; ".join(
            [
                "default-src 'none'",
                f"style-src {_hash_source(parts['style'])}",
                f"script-src {_hash_source(parts['script'])}",
                "base-uri 'none'",
                "form-action 'none'",
            ]
        )
        assert parts["style"] == _asset("explorer.css")
        assert parts["script"] == _asset("explorer.js")

    def test_one_script_one_stylesheet_and_inert_data(self, page):
        assert page.count("<script") == 2
        assert page.count(DATA_OPEN) == 1
        assert page.count("<style") == 1

    def test_no_reference_leaves_the_page(self, page):
        assert not re.search(r"https?:|//[a-z]|\b(src|href|srcset|action|xmlns)\s*=|url\(|@import", page, re.I)
        assert not re.search(r"<(link|img|iframe|frame|object|embed|base|form|audio|video|source)\b", page, re.I)

    def test_no_inline_style_attributes(self):
        # The CSP refuses style="" markup; styling goes through the stylesheet or CSSOM.
        assert 'style="' not in _asset("explorer.html")
        assert "setAttribute(\"style\"" not in _asset("explorer.js")

    @pytest.mark.parametrize(
        "what, pattern",
        [
            ("storage", r"\b(localStorage|sessionStorage|indexedDB|caches|cookieStore)\b|document\.cookie"),
            ("network", r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|Worker|SharedWorker|importScripts|sendBeacon)\b|\bimport\s*\("),
            ("navigation", r"\b(location|history)\s*\.|window\.(open|top|parent|opener)|postMessage|\.submit\("),
            ("markup sinks", r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser|createContextualFragment"),
            ("code from strings", r"\beval\b|new Function|setTimeout|setInterval"),
        ],
    )
    def test_script_avoids(self, what, pattern):
        assert not re.search(pattern, _asset("explorer.js")), what

    def test_assets_are_ascii_and_cannot_close_their_element(self):
        script, style = _asset("explorer.js"), _asset("explorer.css")
        assert script.isascii() and style.isascii()
        assert not re.search(r"</script|<!--", script, re.I)
        assert not re.search(r"</style", style, re.I)

    def test_data_round_trips(self, page, graph):
        assert json.loads(_parts(page)["data"]) == graph

    def test_hostile_values_stay_text(self):
        page = generate_visualizer_html(_hostile_config(), title=HOSTILE_TITLE)
        assert page.count("<script") == 2 and page.count("</script>") == 2
        assert page.count("<style") == 1 and page.count("</style>") == 1
        assert page.count(_asset("explorer.js")) == 1  # the placeholder text was not substituted
        data = _parts(page)["data"]
        assert not re.search(r"[<>&]", data)
        labels = {n["id"]: n for n in json.loads(data)["nodes"]}
        assert labels["user:ann"]["label"] == HOSTILE
        assert labels["policy:x-access"]["sub"] == HOSTILE
        assert "<title>&lt;b&gt;Owned&lt;/b&gt; &amp; co</title>" in page
        assert '<h1 class="title">&lt;b&gt;Owned&lt;/b&gt; &amp; co</h1>' in page

    def test_default_title(self):
        page = generate_visualizer_html(IAMConfig())
        assert "<title>IAMKit Access Graph Explorer</title>" in page

    def test_same_config_same_bytes(self, acme, page):
        assert generate_visualizer_html(acme, title=ACME_TITLE) == page
        assert generate_visualizer_html(_reversed(acme), title=ACME_TITLE) == page

    def test_committed_explorer_is_current(self, page):
        assert COMMITTED_EXPLORER.read_text(encoding="utf-8") == page, (
            "visualization/iam_explorer.html is stale: run `uv run python -m examples.acme.visualize`"
        )

    def test_assets_ship_inside_the_package(self):
        shipped = {p.name for p in files("iamkit.export").joinpath("explorer").iterdir()}
        assert {"explorer.html", "explorer.css", "explorer.js"} <= shipped


# -- the explorer in a real browser -------------------------------------------------------


def _find_chrome() -> str | None:
    configured = os.environ.get("IAMKIT_CHROME")
    if configured:
        return configured
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    return str(mac) if mac.exists() else None


CHROME = _find_chrome()


def _render(page_html: str, tmp_path: Path) -> str:
    """Load the page in headless Chrome and return the DOM after its script ran."""
    page = tmp_path / "explorer.html"
    page.write_text(page_html, encoding="utf-8")
    args = [CHROME, "--headless=new", "--disable-gpu", f"--user-data-dir={tmp_path / 'profile'}"]
    if sys.platform.startswith("linux"):
        # Linux CI runners refuse Chrome's user-namespace sandbox; the page
        # is the file this test just wrote.
        args.append("--no-sandbox")
    result = subprocess.run([*args, "--dump-dom", page.as_uri()], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _default_view(graph: dict) -> tuple[int, int]:
    """Nodes and edges the explorer draws on load: the default environment,
    a policy following its group, every kind and ownership edge shown."""
    env = graph["defaultEnvironment"]
    env_of = {n["id"]: n["env"] for n in graph["nodes"]}
    beam = {e["target"]: e["source"] for e in graph["edges"] if e["kind"] == "policy"}

    def shown(node: dict) -> bool:
        if node["env"]:
            return node["env"] == env
        if node["kind"] == "policy" and node["id"] in beam:
            return env_of[beam[node["id"]]] in (None, env)
        return True

    visible = {n["id"] for n in graph["nodes"] if shown(n)}
    edges = [e for e in graph["edges"] if {e["source"], e["target"]} <= visible]
    return len(visible), len(edges)


@pytest.mark.skipif(CHROME is None, reason="no Chrome or Chromium found; set IAMKIT_CHROME to run the real-browser checks")
class TestExplorerInBrowser:
    @pytest.mark.parametrize("which", ["acme", "empty"])
    def test_renders_under_its_own_csp(self, which, acme, tmp_path):
        config = acme if which == "acme" else IAMConfig()
        dom = _render(generate_visualizer_html(config, title=ACME_TITLE), tmp_path)
        # data-ready is set by the last line of the script, so the script ran
        # to completion under the hash-pinned CSP.
        assert 'data-ready="true"' in dom
        nodes, edges = _default_view(build_access_graph(config))
        assert f'data-rendered-nodes="{nodes}"' in dom
        assert f'data-rendered-edges="{edges}"' in dom

    def test_hostile_values_render_as_text(self, tmp_path):
        dom = _render(generate_visualizer_html(_hostile_config(), title=HOSTILE_TITLE), tmp_path)
        assert 'data-ready="true"' in dom
        assert dom.count("<script") == 2
        assert not re.search(r"<img\b", dom)
        assert "&lt;img src=x onerror=alert(2)&gt;" in dom
