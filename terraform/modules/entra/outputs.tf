output "user_object_ids" {
  description = "name => object_id for all users (existing data sources + managed)"
  value = merge(
    { for k, v in data.azuread_user.existing_users : k => v.object_id },
    { for k, v in azuread_user.managed_users : k => v.object_id },
  )
}

output "security_group_object_ids" {
  description = "group name => object_id"
  value       = { for k, v in azuread_group.security_groups : k => v.object_id }
}

output "license_group_object_ids" {
  description = "group name => object_id"
  value       = { for k, v in azuread_group.license_groups : k => v.object_id }
}

output "m365_group_object_ids" {
  description = "group name => object_id"
  value       = { for k, v in azuread_group.m365_groups : k => v.object_id }
}
