package main.rbac

# <-- Role definitions, static for now...

viewer_role := {
	"role_id": "viewer",
	"resource_actions": [{
		"type": "elasticsearch",
		"actions": ["read"],
	}],
}

editor_role := {
	"role_id": "editor",
	"resource_actions": array.concat(
		viewer_role.resource_actions,
		[{
			"type": "elasticsearch",
			"actions": ["edit"],
		}],
	),
}

admin_role := {
	"role_id": "admin",
	"resource_actions": array.concat(
		editor_role.resource_actions,
		[{
			"type": "elasticsearch",
			"actions": ["create"],
		}],
	),
}

roles := [viewer_role, editor_role, admin_role]

#     Role definitions, static for now... -->
