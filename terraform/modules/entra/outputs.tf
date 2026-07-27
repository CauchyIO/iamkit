output "user_object_ids" {
  description = "name => object_id for all users (existing data sources + managed)"
  value = merge(
    { for k, v in data.azuread_user.existing_users : k => v.object_id },
    { for k, v in azuread_user.managed_users : k => v.object_id },
  )
}

output "managed_user_initial_passwords" {
  description = <<-EOT
    name => the password this module generated when it created that user.

    Only meaningful for users Terraform actually created. For users that predate
    the module (or whose password has since been changed in the portal) the value
    is stale, because `password` is in the azuread_user ignore_changes list and
    is therefore never reconciled after create.

    Retrieve with:
      terraform output -json managed_user_initial_passwords | jq -r '.<name>'

    Hand it over out of band and have the new joiner change it at first sign-in.
  EOT
  value       = { for k, v in random_password.managed_user_initial : k => v.result }
  sensitive   = true
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
