"""Render an IAMConfig as a self-contained, interactive access explorer.

The explorer draws the two planes of the access model. Plane 1 is identity
and directory: users, guests, non-human principals and the groups that hold
them, with their owners. Plane 2 is access: the AccessPolicy beams leaving
each group for GitHub, Linear, Entra and Azure, SharePoint, and the declared
Applications and their workspaces. A security group whose members are all
non-human is drawn as an agent group, answered for by its human owners.

`build_access_graph` compiles the config into plain data: nodes, edges, and
the effective-access rows behind the explorer's table view. GitHub and Linear
rows mirror their exporters exactly (direct members with a GitHub handle;
declared `group_memberships` with a Linear identity); every other grant
reaches a principal through direct or nested group membership.

`generate_visualizer_html` wraps that data in one HTML file with its styles
and script inline. A Content-Security-Policy pinned to the hashes of that
script and stylesheet blocks every network request, and the script touches no
storage, cookies or navigation, so the file works offline and inside an
iframe sandboxed with nothing but allow-scripts.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from collections import deque
from importlib.resources import files
from typing import Any

from iamkit.export.terraform import _GITHUB_PERMISSION_MAP
from iamkit.models.access import GitHubAccessSpec, LinearAccessSpec
from iamkit.models.config import IAMConfig
from iamkit.models.enums import Environment, PermissionLevel, PrincipalType
from iamkit.models.groups import LicenseGroup, M365Group, MailingList, SecurityGroup

_NON_HUMAN = frozenset({"service_principal", "managed_identity"})


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _joined(values: list[str] | tuple[str, ...]) -> str:
    return ", ".join(values)


def _github_permission(level: PermissionLevel) -> str:
    return _GITHUB_PERMISSION_MAP.get(level.value, level.value)


def _github_grant(spec: GitHubAccessSpec) -> str:
    parts: list[str] = []
    if spec.all_repositories is not None:
        text = f"{_github_permission(spec.all_repositories)} on all repositories"
        if spec.exclude_repositories:
            text += f" except {_joined(sorted(spec.exclude_repositories))}"
        parts.append(text)
    for repo, level in sorted(spec.repositories.items()):
        parts.append(f"{_github_permission(level)} on {repo}")
    return "; ".join(parts) or "team membership"


def _linear_grant(spec: LinearAccessSpec) -> str:
    if spec.teams:
        return f"{spec.role.value} · teams {_joined(sorted(spec.teams))}"
    return spec.role.value


def _node(
    node_id: str,
    kind: str,
    name: str,
    label: str,
    sub: str,
    *,
    env: str | None = None,
    props: list[tuple[str, str | None]] | None = None,
    badges: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "kind": kind,
        "name": name,
        "label": label,
        "sub": sub,
        "env": env,
        "agent": False,
        "props": [[key, value] for key, value in (props or []) if value],
        "badges": [{"tone": tone, "text": text} for tone, text in (badges or [])],
    }


class _GraphBuilder:
    def __init__(self, config: IAMConfig) -> None:
        self.config = config
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.rows: list[dict[str, Any]] = []
        # Bare config names resolve to node ids through one map: principals
        # and groups share a single namespace (IAM-P08).
        self.refs: dict[str, str] = {}
        self.user_by_handle = {
            user.platform_config.github.handle: key
            for key, user in config.users.items()
            if user.platform_config.github is not None
        }

    # -- primitives ---------------------------------------------------------

    def add(self, node: dict[str, Any]) -> str:
        return self.nodes.setdefault(node["id"], node)["id"]

    def link(self, kind: str, source: str, target: str, **extra: Any) -> None:
        self.edges.append({"kind": kind, "source": source, "target": target, **extra})

    def resolve(self, name: str) -> str:
        node_id = self.refs.get(name)
        return node_id if node_id is not None else self.unresolved(name)

    def unresolved(self, name: str) -> str:
        # Owners and RBAC group names are not cross-validated by IAMConfig;
        # draw what they point at rather than dropping the reference.
        return self.add(
            _node(
                f"unresolved:{name}",
                "unresolved",
                name,
                name,
                "unresolved reference",
                badges=[("critical", "Referenced in the config but declared nowhere")],
            )
        )

    def group_key(self, name: str) -> str | None:
        if name in self.config.groups:
            return name
        for key, group in self.config.groups.items():
            if isinstance(group, SecurityGroup) and group.resolved_name == name:
                return key
        return None

    # -- plane 1: principals and groups --------------------------------------

    def principals(self) -> None:
        config = self.config
        for key, user in sorted(config.users.items()):
            github = user.platform_config.github
            linear = user.platform_config.linear
            badges: list[tuple[str, str]] = []
            if not user.managed:
                badges.append(("info", "Data source only: never Terraform-managed (IAM-P03)"))
            if not user.account_enabled:
                badges.append(("warning", "Account disabled"))
            self.refs[key] = self.add(
                _node(
                    f"user:{key}",
                    "user",
                    key,
                    user.display_name,
                    user.email,
                    props=[
                        ("Name", key),
                        ("Email", user.email),
                        ("GitHub", f"{github.handle} · org {github.org_role.value}" if github else None),
                        ("Linear", f"{linear.email} · {linear.role.value}" if linear else None),
                        ("Managed", _yes_no(user.managed)),
                        ("Account enabled", _yes_no(user.account_enabled)),
                        ("Usage location", user.usage_location),
                        ("Department", user.department),
                        ("Job title", user.job_title),
                        ("Manager", user.manager),
                        ("Aliases", _joined(sorted(user.aliases))),
                    ],
                    badges=badges,
                )
            )
        for key, guest in sorted(config.external_users.items()):
            self.refs[key] = self.add(
                _node(
                    f"guest:{key}",
                    "external_user",
                    key,
                    guest.display_name,
                    guest.email,
                    props=[("Name", key), ("Email", guest.email)],
                    badges=[("info", "B2B guest invited from another directory (IAM-P05)")],
                )
            )
        for key, sp in sorted(config.service_principals.items()):
            self.refs[key] = self.add(
                _node(
                    f"sp:{key}",
                    "service_principal",
                    key,
                    sp.display_name or key,
                    "service principal",
                    props=[
                        ("Name", key),
                        ("Application ID", sp.application_id),
                        ("Source", sp.source.value),
                        ("Entitlements", _joined(sorted(sp.entitlements))),
                    ],
                )
            )
        for key, mi in sorted(config.managed_identities.items()):
            self.refs[key] = self.add(
                _node(
                    f"mi:{key}",
                    "managed_identity",
                    key,
                    key,
                    "managed identity",
                    props=[
                        ("Name", key),
                        ("Resource group", mi.resource_group),
                        ("Location", mi.location),
                    ],
                )
            )
        for key, mailbox in sorted(config.shared_mailboxes.items()):
            self.refs[key] = self.add(
                _node(
                    f"mailbox:{key}",
                    "shared_mailbox",
                    key,
                    mailbox.display_name,
                    mailbox.email_address,
                    props=[
                        ("Name", key),
                        ("Email", mailbox.email_address),
                        ("Delegates", _joined(sorted(mailbox.delegates))),
                    ],
                )
            )

    def groups(self) -> None:
        config = self.config
        for key, group in sorted(config.groups.items()):
            if isinstance(group, LicenseGroup):
                kind, type_label = "license_group", "license group"
            elif isinstance(group, SecurityGroup):
                kind, type_label = "security_group", "security group"
            elif isinstance(group, M365Group):
                kind, type_label = "m365_group", "Microsoft 365 group"
            else:
                kind, type_label = "mailing_list", "mailing list"
            resolved = group.resolved_name if isinstance(group, SecurityGroup) else group.name
            env = (
                group.environment.value
                if isinstance(group, SecurityGroup) and group.environment is not None
                else None
            )
            owners = getattr(group, "owners", [])
            props: list[tuple[str, str | None]] = [
                ("Name", key),
                ("Resolved name", resolved),
                ("Type", type_label),
                ("Environment", env.upper() if env else "all environments"),
                ("Description", getattr(group, "description", None)),
                ("Members", str(len(group.members))),
                ("Owners", _joined(sorted(o.name for o in owners)) if owners else None),
            ]
            if isinstance(group, SecurityGroup):
                props.append(("Assignable to role", _yes_no(group.assignable_to_role)))
            if isinstance(group, LicenseGroup):
                props.append(("SKU", group.sku))
            if isinstance(group, MailingList):
                props.append(("Email", group.email_address))
            self.refs[key] = self.add(
                _node(
                    f"group:{key}",
                    kind,
                    key,
                    group.display_name or resolved,
                    resolved,
                    env=env,
                    props=props,
                )
            )

    def memberships(self) -> None:
        config = self.config
        human_kinds = {"user", "external_user"}
        for key, group in sorted(config.groups.items()):
            group_id = self.refs[key]
            member_kinds: list[str] = []
            for member in group.members:
                member_id = self.resolve(member.name)
                member_kinds.append(self.nodes[member_id]["kind"])
                self.link("member", member_id, group_id)
            node = self.nodes[group_id]
            if not hasattr(group, "owners"):
                continue  # mailing lists carry no owners
            owner_kinds: list[str] = []
            for owner in group.owners:
                owner_id = self.resolve(owner.name)
                owner_kinds.append(self.nodes[owner_id]["kind"])
                self.link("owner", owner_id, group_id)
            if not group.owners:
                node["badges"].append(
                    {"tone": "critical", "text": "No owner: an entitlement nobody answers for (IAM-P01)"}
                )
            elif not human_kinds.intersection(owner_kinds):
                node["badges"].append({"tone": "warning", "text": "No human owner (IAM-P01)"})
            if member_kinds and all(kind in _NON_HUMAN for kind in member_kinds):
                node["agent"] = True
                node["badges"].append(
                    {
                        "tone": "info",
                        "text": "Agent group: non-human members, answered for by its owners (IAM-P06)",
                    }
                )
            if not group.members:
                node["badges"].append({"tone": "info", "text": "No members"})

    # -- plane 2: policies, platforms, applications -------------------------

    def applications(self) -> None:
        for key, app in sorted(self.config.applications.items()):
            app_id = self.add(
                _node(
                    f"app:{key}",
                    "application",
                    key,
                    app.display_name,
                    f"{key} · {app.source.value}",
                    props=[
                        ("Name", key),
                        ("Source", app.source.value),
                        ("Application ID", app.application_id),
                        ("Audience", app.audience),
                        ("Redirect URIs", _joined(sorted(app.redirect_uris))),
                        ("Roles", _joined(app.available_roles)),
                        ("Scopes", _joined(sorted(app.available_scopes))),
                        ("Workspaces", _joined(sorted(app.workspaces))),
                    ],
                )
            )
            for slug in sorted(app.workspaces):
                workspace_id = self.add(
                    _node(f"workspace:{slug}", "workspace", slug, slug, "workspace")
                )
                self.link("workspace", app_id, workspace_id, workspace=slug)
        for slug in sorted(n["name"] for n in self.nodes.values() if n["kind"] == "workspace"):
            declaring = sorted(
                key for key, app in self.config.applications.items() if slug in app.workspaces
            )
            self.nodes[f"workspace:{slug}"]["props"] = [
                ["Slug", slug],
                ["Applications", _joined(declaring)],
            ]

    def policies(self) -> None:
        config = self.config
        for key, policy in sorted(config.access_policies.items()):
            badges: list[tuple[str, str]] = []
            if policy.group is None:
                badges.append(("info", "No group: holds only GitHub handles outside the directory"))
            policy_id = self.add(
                _node(
                    f"policy:{key}",
                    "policy",
                    key,
                    key,
                    policy.description or (f"group {policy.group}" if policy.group else "no group"),
                    props=[
                        ("Name", key),
                        ("Group", policy.group),
                        ("Description", policy.description),
                        ("Entra roles", _joined(sorted(policy.entra_roles))),
                        ("Conditional access groups", _joined(sorted(policy.conditional_access_groups))),
                    ],
                    badges=badges,
                )
            )
            if policy.group is not None:
                self.link("policy", self.resolve(policy.group), policy_id)

            if policy.github is not None:
                spec = policy.github
                team_id = self.add(
                    _node(
                        f"github:{spec.team_name}",
                        "github_team",
                        spec.team_name,
                        spec.team_name,
                        "GitHub team",
                        props=[
                            ("Team", spec.team_name),
                            ("Grant", _github_grant(spec)),
                            ("External members", _joined(sorted(spec.external_members))),
                        ],
                    )
                )
                self.link("grant", policy_id, team_id, label=_github_grant(spec))
                for handle in spec.external_members:
                    user_key = self.user_by_handle.get(handle)
                    if user_key is not None:
                        source = self.refs[user_key]
                    else:
                        source = self.add(
                            _node(
                                f"handle:{handle}",
                                "github_handle",
                                handle,
                                handle,
                                "GitHub handle",
                                props=[("Handle", handle)],
                                badges=[
                                    (
                                        "info",
                                        "GitHub identity outside the directory: access held "
                                        "through a policy's external members, not a group",
                                    )
                                ],
                            )
                        )
                    self.link("external_member", source, policy_id, label=f"GitHub handle {handle}")

            if policy.linear is not None:
                linear_id = self.add(_node("linear", "linear", "linear", "Linear", "workspace"))
                self.link("grant", policy_id, linear_id, label=_linear_grant(policy.linear))

            for role in sorted(policy.entra_roles):
                role_id = self.add(
                    _node(
                        f"entra:{role}",
                        "entra_role",
                        role,
                        role,
                        "Entra directory role",
                        props=[("Role", role)],
                    )
                )
                self.link("grant", policy_id, role_id, label="directory role")

            if policy.sharepoint is not None:
                for site, level in sorted(policy.sharepoint.sites.items()):
                    site_id = self.add(
                        _node(
                            f"sharepoint:{site}",
                            "sharepoint_site",
                            site,
                            site,
                            "SharePoint site",
                            props=[("Site", site)],
                        )
                    )
                    self.link("grant", policy_id, site_id, label=level.value)

            for spec in policy.applications:
                self.link(
                    "grant",
                    policy_id,
                    f"app:{spec.application}",
                    label=spec.role,
                    role=spec.role,
                    workspaces=sorted(spec.workspaces),
                    scopes=sorted(spec.scopes),
                )

    def role_assignments(self) -> None:
        for assignment in self.config.azure_role_assignments:
            target = self.add(
                _node(
                    f"rbac:{assignment.role}@{assignment.scope}",
                    "azure_rbac",
                    f"{assignment.role}@{assignment.scope}",
                    assignment.role,
                    f"Azure RBAC · {assignment.scope}",
                    props=[("Role", assignment.role), ("Scope", assignment.scope)],
                )
            )
            group_key = self.group_key(assignment.group_name)
            source = self.refs[group_key] if group_key else self.unresolved(assignment.group_name)
            self.link("rbac", source, target, label=f"{assignment.role} @ {assignment.scope}")

    # -- effective access ----------------------------------------------------

    def row(self, principal: str, target: str, grant: str, **extra: Any) -> None:
        self.rows.append(
            {
                "principal": principal,
                "target": target,
                "grant": grant,
                "via": extra.get("via", []),
                "policy": extra.get("policy"),
                "workspaces": extra.get("workspaces", []),
                "scopes": extra.get("scopes", []),
                "envs": extra.get("envs", []),
            }
        )

    def group_envs(self, keys: tuple[str, ...]) -> list[str]:
        envs: set[str] = set()
        for key in keys:
            group = self.config.groups[key]
            if isinstance(group, SecurityGroup) and group.environment is not None:
                envs.add(group.environment.value)
        return sorted(envs)

    def group_paths(self, name: str) -> list[tuple[str, tuple[str, ...]]]:
        """Groups `name` belongs to, directly or through nesting, with the path."""
        groups = self.config.groups
        parents: dict[str, list[str]] = {key: [] for key in groups}
        for key, group in groups.items():
            for member in group.members:
                if member.principal_type == PrincipalType.GROUP and member.name in parents:
                    parents[member.name].append(key)
        queue = deque(
            (key, (key,))
            for key, group in sorted(groups.items())
            if any(
                m.name == name and m.principal_type != PrincipalType.GROUP for m in group.members
            )
        )
        seen: set[str] = set()
        paths: list[tuple[str, tuple[str, ...]]] = []
        while queue:
            key, path = queue.popleft()
            if key in seen:
                continue
            seen.add(key)
            paths.append((key, path))
            for parent in sorted(parents[key]):
                queue.append((parent, path + (parent,)))
        return paths

    def effective_access(self) -> None:
        config = self.config
        policies = sorted(config.access_policies.items())

        # GitHub, as TerraformExporter.export_github_tfvars derives teams:
        # direct members who are enabled users with a handle, plus external
        # handles listed on the policy itself.
        for key, policy in policies:
            if policy.github is None:
                continue
            team = f"github:{policy.github.team_name}"
            grant = _github_grant(policy.github)
            # External handles hold the team without the group, but only in
            # the environments the policy's group exists in.
            envs: list[str] = []
            if policy.group is not None and policy.group in config.groups:
                envs = self.group_envs((policy.group,))
                for member in config.groups[policy.group].members:
                    user = config.users.get(member.name)
                    if user and user.account_enabled and user.platform_config.github:
                        self.row(
                            self.refs[member.name],
                            team,
                            grant,
                            via=[self.refs[policy.group]],
                            policy=f"policy:{key}",
                            envs=envs,
                        )
            for handle in policy.github.external_members:
                user_key = self.user_by_handle.get(handle)
                principal = self.refs[user_key] if user_key else f"handle:{handle}"
                self.row(principal, team, grant, policy=f"policy:{key}", envs=envs)

        # Linear, as executors.linear.resolve_desired_state derives roles:
        # enabled users with a Linear identity, through declared memberships.
        for user_key, user in sorted(config.users.items()):
            if user.platform_config.linear is None or not user.account_enabled:
                continue
            for key, policy in policies:
                if policy.group is None or policy.linear is None:
                    continue
                if policy.group in user.group_memberships:
                    self.row(
                        self.refs[user_key],
                        "linear",
                        _linear_grant(policy.linear),
                        via=[self.refs[policy.group]],
                        policy=f"policy:{key}",
                        envs=self.group_envs((policy.group,)),
                    )

        # Everything else reaches a principal through group membership,
        # nesting included. A disabled account signs in to nothing, so it
        # keeps its membership edges but holds no row, as in the exporters.
        principals = (
            list(config.users)
            + list(config.external_users)
            + list(config.service_principals)
            + list(config.managed_identities)
            + list(config.shared_mailboxes)
        )
        for name in sorted(principals):
            user = config.users.get(name)
            if user is not None and not user.account_enabled:
                continue
            principal = self.refs[name]
            for group_key, path in self.group_paths(name):
                via = [self.refs[k] for k in path]
                envs = self.group_envs(path)
                for key, policy in policies:
                    if policy.group != group_key:
                        continue
                    policy_id = f"policy:{key}"
                    for role in sorted(policy.entra_roles):
                        self.row(principal, f"entra:{role}", "directory role",
                                 via=via, policy=policy_id, envs=envs)
                    if policy.sharepoint is not None:
                        for site, level in sorted(policy.sharepoint.sites.items()):
                            self.row(principal, f"sharepoint:{site}", level.value,
                                     via=via, policy=policy_id, envs=envs)
                    for spec in policy.applications:
                        self.row(
                            principal,
                            f"app:{spec.application}",
                            spec.role,
                            via=via,
                            policy=policy_id,
                            workspaces=sorted(spec.workspaces),
                            scopes=sorted(spec.scopes),
                            envs=envs,
                        )
                for assignment in config.azure_role_assignments:
                    if self.group_key(assignment.group_name) == group_key:
                        self.row(
                            principal,
                            f"rbac:{assignment.role}@{assignment.scope}",
                            f"{assignment.role} @ {assignment.scope}",
                            via=via,
                            envs=envs,
                        )

    # -- assembly -------------------------------------------------------------

    def build(self) -> dict[str, Any]:
        self.principals()
        self.groups()
        self.memberships()
        self.applications()
        self.policies()
        self.role_assignments()
        self.effective_access()

        edges = sorted(
            self.edges,
            key=lambda e: (
                e["kind"],
                e["source"],
                e["target"],
                e.get("label", ""),
                e.get("workspaces", []),
                e.get("scopes", []),
            ),
        )
        for index, edge in enumerate(edges):
            edge["id"] = f"e{index}"
        rows = sorted(
            self.rows,
            key=lambda r: (r["principal"], r["target"], r["grant"], r["policy"] or "", r["via"]),
        )
        return {
            "environments": [env.value for env in Environment],
            "defaultEnvironment": Environment.PRD.value,
            "nodes": [self.nodes[key] for key in sorted(self.nodes)],
            "edges": edges,
            "rows": rows,
        }


def build_access_graph(config: IAMConfig) -> dict[str, Any]:
    """Compile `config` into the explorer's data: nodes, edges and access rows.

    Deterministic for a given config, and plain JSON-serializable data.
    """
    return _GraphBuilder(config).build()


def _asset(name: str) -> str:
    return files("iamkit.export").joinpath("explorer").joinpath(name).read_text(encoding="utf-8")


def _csp_source(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def _script_json(data: dict[str, Any]) -> str:
    # Inside <script type="application/json"> only "</script" could end the
    # block early; escaping every <, > and & keeps config values inert.
    text = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def generate_visualizer_html(
    config: IAMConfig, title: str = "IAMKit Access Graph Explorer"
) -> str:
    """Render `config` as one self-contained HTML access explorer.

    Same config and title, same bytes: no timestamps, sorted data. The page
    makes no network request (its CSP is `default-src 'none'` with the inline
    script and stylesheet pinned by hash) and uses no storage or cookies.
    """
    style = _asset("explorer.css")
    script = _asset("explorer.js")
    csp = "; ".join(
        [
            "default-src 'none'",
            f"style-src {_csp_source(style)}",
            f"script-src {_csp_source(script)}",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )
    values = {
        "TITLE": html.escape(title, quote=True),
        "CSP": csp,
        "STYLE": style,
        "SCRIPT": script,
        "DATA": _script_json(build_access_graph(config)),
    }
    # One pass over the template: substituted text is never rescanned, so a
    # config value that happens to spell a placeholder stays literal.
    return re.sub(r"__IAMKIT_([A-Z]+)__", lambda m: values[m.group(1)], _asset("explorer.html"))
