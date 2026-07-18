# -----------------------------------------------------------------------------
# iamkit GitHub org module — members, teams, repo permissions
#
# Manages org settings, memberships, teams, team memberships, and repository
# access permissions. Org-level defaults (e.g. no default repo access) are set
# here; per-team repo grants are driven by access policies in config/.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Org settings
# -----------------------------------------------------------------------------

resource "github_organization_settings" "org" {
  count = var.github_org_settings == null ? 0 : 1

  name                            = var.github_org_settings.name
  billing_email                   = var.github_org_settings.billing_email
  email                           = var.github_org_settings.email
  blog                            = var.github_org_settings.blog
  location                        = var.github_org_settings.location
  default_repository_permission   = var.github_org_settings.default_repository_permission
  members_can_create_repositories = var.github_org_settings.members_can_create_repositories
}

# -----------------------------------------------------------------------------
# Org membership
# -----------------------------------------------------------------------------

resource "github_membership" "members" {
  for_each = { for m in var.github_members : m.username => m }

  username = each.value.username
  role     = each.value.role
}

# -----------------------------------------------------------------------------
# Teams
# -----------------------------------------------------------------------------

resource "github_team" "teams" {
  for_each = { for t in var.github_teams : t.name => t }

  name    = each.value.name
  privacy = "closed"
}


# -----------------------------------------------------------------------------
# Team ↔ repository permissions (explicit repos)
# -----------------------------------------------------------------------------

locals {
  team_repos = flatten([
    for team in var.github_teams : [
      for repo, permission in team.repositories : {
        team_name  = team.name
        repository = repo
        permission = permission
      }
    ]
  ])

  # Teams that grant a permission level to every org repo.
  all_repo_teams = [
    for team in var.github_teams : team if team.all_repositories != null
  ]
}

resource "github_team_repository" "repos" {
  for_each = { for tr in local.team_repos : "${tr.team_name}/${tr.repository}" => tr }

  team_id    = github_team.teams[each.value.team_name].id
  repository = each.value.repository
  permission = each.value.permission
}

# -----------------------------------------------------------------------------
# Team ↔ repository permissions (all_repositories)
#
# For admin-style teams that need a blanket permission on every repo,
# we enumerate org repos via a data source and create one association each.
# -----------------------------------------------------------------------------

data "github_repositories" "org" {
  count = length(local.all_repo_teams) > 0 ? 1 : 0
  query = "org:${var.github_org}"
}

locals {
  all_repo_team_repos = flatten([
    for team in local.all_repo_teams : [
      for repo in try(data.github_repositories.org[0].names, []) : {
        team_name  = team.name
        repository = repo
        permission = team.all_repositories
      }
      if !contains(team.exclude_repositories, repo) && !contains(keys(team.repositories), repo)
    ]
  ])
}

resource "github_team_repository" "all_repos" {
  for_each = { for tr in local.all_repo_team_repos : "${tr.team_name}/${tr.repository}" => tr }

  team_id    = github_team.teams[each.value.team_name].id
  repository = each.value.repository
  permission = each.value.permission
}

# -----------------------------------------------------------------------------
# Team membership — derived from access policy → group + external members
# -----------------------------------------------------------------------------

locals {
  team_members = flatten([
    for team in var.github_teams : [
      for username in team.members : {
        team_name = team.name
        username  = username
      }
    ]
  ])
}

resource "github_team_membership" "members" {
  for_each = { for tm in local.team_members : "${tm.team_name}/${tm.username}" => tm }

  team_id  = github_team.teams[each.value.team_name].id
  username = each.value.username
  role     = contains(keys({ for m in var.github_members : m.username => m if m.role == "admin" }), each.value.username) ? "maintainer" : "member"
}

