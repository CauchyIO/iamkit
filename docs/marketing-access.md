# Marketing ACL handoff

`AccessPolicy.marketing = MarketingAccessSpec(workspaces={"acme": MarketingRole.OWNER})`
grants the policy's security group ownership of the `acme` Marketing workspace.
The other supported role is `VIEWER`. `operator=True` explicitly grants platform
operator authority; it is independent of workspace roles and defaults to false.

Export using `iamkit.export.export_marketing_bindings(config,
entra_tenant_id="<directory UUID>", group_ids={"sg-admin": "<group object UUID>"})`.
The result is a versioned JSON document for Marketing's `enroll-entra-acl` command.
It is application configuration and is deliberately separate from Terraform
variable files. Omitting `group_ids` emits resolved group names instead; the
trusted sign-in issuer must then emit exactly those names. Prefer immutable
object IDs in production. Passing a partial ID mapping is an error.

Merge the `bindings` arrays from each directory's export into one version-1
document before enrollment. Every binding carries its own Entra tenant ID;
an identically named group in another directory carries no authority.
An empty workspace map grants no workspace. An empty document revokes the
managed configuration when enrolled, rather than meaning all workspaces.
