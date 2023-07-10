package main.workspaces

import future.keywords

# TODO: check if this is cached...otherwise we should just send it in as external data
# We also assume Workspace Ids are UUIDs (unique across Orgs)
resource_id_to_workspaces_set := {resource_id: workspaces_set |
	some _, workspace_def in data.workspaces
	some resource_id in workspace_def.resource_ids
	workspaces_set := {workspace_details |
		some workspace_id, inner_workspace_def in data.workspaces
		resource_id in inner_workspace_def.resource_ids
		workspace_details := workspace_id
	}
}
