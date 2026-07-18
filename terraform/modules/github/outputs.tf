output "team_ids" {
  description = "team name => team id"
  value       = { for k, v in github_team.teams : k => v.id }
}

output "team_node_ids" {
  description = "team name => GraphQL node id (for branch protection push allowances)"
  value       = { for k, v in github_team.teams : k => v.node_id }
}
