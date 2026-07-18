# -----------------------------------------------------------------------------
# iamkit Entra ID module — users, groups, licenses, role assignments
#
# Provisions users, security groups, license groups, M365 groups, and Azure
# RBAC role assignments. Board members are read-only data sources; all other
# users are fully managed by Terraform.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Board members — data source only, NEVER managed by Terraform
# -----------------------------------------------------------------------------

data "azuread_user" "existing_users" {
  for_each            = { for u in var.iam_users_existing : u.name => u }
  user_principal_name = each.value.email
}

# -----------------------------------------------------------------------------
# Managed users — full lifecycle via Terraform
# -----------------------------------------------------------------------------

resource "azuread_user" "managed_users" {
  for_each = { for u in var.iam_users_managed : u.name => u }

  user_principal_name = each.value.email
  display_name        = each.value.display_name
  account_enabled     = each.value.account_enabled
  usage_location      = each.value.usage_location
  department          = each.value.department
  job_title           = each.value.job_title
  mail_nickname       = each.key

  lifecycle {
    ignore_changes = [
      password,
      given_name,
      surname,
      force_password_change,
    ]
  }
}

# -----------------------------------------------------------------------------
# External (B2B guest) users — invited, then addressable as group members
# -----------------------------------------------------------------------------

resource "azuread_invitation" "external_users" {
  for_each = { for eu in var.iam_external_users : eu.name => eu }

  user_email_address = each.value.email
  user_display_name  = each.value.display_name
  redirect_url       = each.value.invitation_redirect_url

  dynamic "message" {
    for_each = each.value.send_invitation ? [1] : []
    content {}
  }
}

locals {
  user_object_ids = merge(
    { for k, v in data.azuread_user.existing_users : k => v.object_id },
    { for k, v in azuread_user.managed_users : k => v.object_id },
    { for k, v in azuread_invitation.external_users : k => v.user_id },
  )
}

# -----------------------------------------------------------------------------
# Security groups
# -----------------------------------------------------------------------------

resource "azuread_group" "security_groups" {
  for_each = { for g in var.iam_security_groups : g.name => g }

  display_name       = each.value.display_name != null ? each.value.display_name : each.value.name
  description        = each.value.description
  security_enabled   = true
  assignable_to_role = each.value.assignable_to_role

  # Owners must be users; group-typed owners are rejected by Entra and the
  # membership guard fails the plan on any name that resolves to nothing.
  owners = [
    for o in each.value.owners : local.user_object_ids[o]
    if contains(keys(local.user_object_ids), o)
  ]

  # Groups carry RBAC role assignments and platform access policies;
  # destroy-recreate silently breaks every permission flowing through them.
  lifecycle {
    prevent_destroy = true
  }
}

locals {
  sg_members = flatten([
    for g in var.iam_security_groups : [
      for m in g.members : {
        group_name = g.name
        user_name  = m
      } if contains(keys(local.principal_object_ids), m)
    ]
  ])
}

resource "azuread_group_member" "security_group_members" {
  for_each = { for sm in local.sg_members : "${sm.group_name}/${sm.user_name}" => sm }

  group_object_id  = azuread_group.security_groups[each.value.group_name].object_id
  member_object_id = local.principal_object_ids[each.value.user_name]
}

# -----------------------------------------------------------------------------
# License groups (security groups that will be assigned licenses at cut-over)
# -----------------------------------------------------------------------------

resource "azuread_group" "license_groups" {
  for_each = { for g in var.iam_license_groups : g.name => g }

  display_name     = each.value.display_name != null ? each.value.display_name : each.value.name
  security_enabled = true

  # License groups drive Microsoft 365 license assignment;
  # destroy-recreate revokes licenses for every member.
  lifecycle {
    prevent_destroy = true
  }
}

locals {
  lg_members = flatten([
    for g in var.iam_license_groups : [
      for m in g.members : {
        group_name = g.name
        user_name  = m
      } if contains(keys(local.principal_object_ids), m)
    ]
  ])
}

resource "azuread_group_member" "license_group_members" {
  for_each = { for lm in local.lg_members : "${lm.group_name}/${lm.user_name}" => lm }

  group_object_id  = azuread_group.license_groups[each.value.group_name].object_id
  member_object_id = local.principal_object_ids[each.value.user_name]
}

# -----------------------------------------------------------------------------
# M365 groups (Unified — provisions SharePoint site + shared mailbox)
# -----------------------------------------------------------------------------

resource "azuread_group" "m365_groups" {
  for_each = { for g in var.iam_m365_groups : g.name => g }

  display_name               = each.value.display_name != null ? each.value.display_name : each.value.name
  description                = each.value.description
  mail_enabled               = true
  mail_nickname              = replace(each.value.name, "-", "")
  security_enabled           = false
  types                      = ["Unified"]
  auto_subscribe_new_members = true

  owners = [
    for o in each.value.owners : local.user_object_ids[o]
    if contains(keys(local.user_object_ids), o)
  ]

  # M365 groups own Teams channels, SharePoint sites, and the group mailbox.
  # Destroy is irreversible — Teams channel content cannot be restored from
  # the recycle bin (only the SharePoint site can). Note mail_nickname is a
  # ForceNew attribute; prevent_destroy hard-fails any destroy-recreate plan.
  lifecycle {
    prevent_destroy = true
  }
}

locals {
  m365_members = flatten([
    for g in var.iam_m365_groups : [
      for m in g.members : {
        group_name = g.name
        user_name  = m
      } if contains(keys(local.principal_object_ids), m)
    ]
  ])
}

resource "azuread_group_member" "m365_group_members" {
  for_each = { for mm in local.m365_members : "${mm.group_name}/${mm.user_name}" => mm }

  group_object_id  = azuread_group.m365_groups[each.value.group_name].object_id
  member_object_id = local.principal_object_ids[each.value.user_name]
}

# -----------------------------------------------------------------------------
# Membership resolution — every referenced member/owner must resolve to a
# managed user, external user, or a group defined in this module. Anything
# else (service principals, typos) fails the plan loudly instead of being
# silently dropped.
# -----------------------------------------------------------------------------

locals {
  principal_object_ids = merge(
    local.user_object_ids,
    { for k, v in azuread_group.security_groups : k => v.object_id },
    { for k, v in azuread_group.license_groups : k => v.object_id },
    { for k, v in azuread_group.m365_groups : k => v.object_id },
  )

  unresolved_members = distinct(flatten([
    [for g in var.iam_security_groups : [
      for m in concat(g.members, g.owners) : m
      if !contains(keys(local.principal_object_ids), m)
    ]],
    [for g in var.iam_license_groups : [
      for m in g.members : m
      if !contains(keys(local.principal_object_ids), m)
    ]],
    [for g in var.iam_m365_groups : [
      for m in concat(g.members, g.owners) : m
      if !contains(keys(local.principal_object_ids), m)
    ]],
  ]))
}

resource "terraform_data" "membership_guard" {
  lifecycle {
    precondition {
      condition     = length(local.unresolved_members) == 0
      error_message = "Unresolved group members/owners: ${join(", ", local.unresolved_members)}"
    }
  }
}

# -----------------------------------------------------------------------------
# Azure RBAC role assignments for security groups
# -----------------------------------------------------------------------------

data "azurerm_subscription" "current" {}

resource "azurerm_role_assignment" "security_group_roles" {
  for_each = { for ra in var.iam_role_assignments : "${ra.group_name}/${ra.role}/${ra.scope}" => ra }

  scope                = each.value.scope == "subscription" ? data.azurerm_subscription.current.id : each.value.scope
  role_definition_name = each.value.role
  principal_id         = azuread_group.security_groups[each.value.group_name].object_id
}
