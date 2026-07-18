# iamkit github module inputs — shape matches TerraformExporter's GITHUB_VARIABLE_SCHEMAS.

variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

variable "github_members" {
  description = "Org members with their roles"
  type = list(object({
    username = string
    role     = string
  }))
}

variable "github_teams" {
  description = "Teams with repo permissions"
  type = list(object({
    name                 = string
    members              = list(string)
    repositories         = map(string)
    all_repositories     = optional(string, null)
    exclude_repositories = list(string)
  }))
}

variable "github_org_settings" {
  description = "Organization-level GitHub settings; null skips org-settings management"
  type = object({
    name                            = string
    billing_email                   = string
    email                           = string
    blog                            = string
    location                        = string
    default_repository_permission   = string
    members_can_create_repositories = bool
  })
  default = null
}
