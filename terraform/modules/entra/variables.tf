# iamkit entra module inputs — shape matches TerraformExporter's ENTRA_VARIABLE_SCHEMAS.

variable "iam_users_existing" {
  description = "Board/unmanaged users — data source lookup only"
  type = list(object({
    name         = string
    display_name = string
    email        = string
  }))
}

variable "iam_users_managed" {
  description = "Terraform-managed Entra ID users"
  type = list(object({
    name            = string
    display_name    = string
    email           = string
    account_enabled = bool
    usage_location  = optional(string, null)
    department      = optional(string, null)
    job_title       = optional(string, null)
  }))
}

variable "iam_security_groups" {
  description = "Security groups with members and owners"
  type = list(object({
    name               = string
    display_name       = optional(string, null)
    description        = optional(string, null)
    assignable_to_role = bool
    members            = list(string)
    owners             = list(string)
  }))
}

variable "iam_license_groups" {
  description = "License groups for group-based licensing"
  type = list(object({
    name           = string
    display_name   = optional(string, null)
    sku            = string
    sku_id         = string
    disabled_plans = list(string)
    members        = list(string)
  }))
}

variable "iam_m365_groups" {
  description = "Microsoft 365 Unified groups"
  type = list(object({
    name         = string
    display_name = optional(string, null)
    description  = optional(string, null)
    members      = list(string)
    owners       = list(string)
  }))
}

variable "iam_role_assignments" {
  description = "Azure RBAC role assignments for security groups"
  type = list(object({
    group_name = string
    role       = string
    scope      = string
  }))
  default = []
}

variable "iam_external_users" {
  description = "B2B guest users invited via azuread_invitation"
  type = list(object({
    name                    = string
    email                   = string
    display_name            = string
    invitation_redirect_url = string
    send_invitation         = bool
  }))
  default = []
}
