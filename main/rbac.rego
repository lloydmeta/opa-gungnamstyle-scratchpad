package main.rbac

import future.keywords

# <-- Role definitions...probably data?
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

#     Role definitions...probably data? -->

retreived_role_assignments(principal_id) := role_assignments if {
	some principal in data.principals
	principal.principal_id == principal_id
	role_assignments := principal.role_assignments
}

retreived_role(role_id) := role if {
	some role in roles
	role.role_id == role_id
}

# all: true
role_assignment_scope_matches(assignment_scope, requested_resource_id) if {
	assignment_scope.all == true
}

# specific resource ids
role_assignment_scope_matches(assignment_scope, requested_resource_id) if {
	some assignment_specific_id in assignment_scope.specific_ids
	assignment_specific_id == requested_resource_id
}

allowed_on(principal_id, resource_type, action, org_id, resource_id) if {
	role_assignments := retreived_role_assignments(principal_id)
	print("role_assignments ", role_assignments)

	some role_assignment in role_assignments

	print("role_assignment ", role_assignment)

	role_assignment.organization_id == org_id

	print("assignment_scope ", role_assignment.scope)

	scope_check_result := role_assignment_scope_matches(role_assignment.scope, resource_id)

	print("scope_check_result ", scope_check_result)
	true == scope_check_result

	role := retreived_role(role_assignment.role_id)

	print("role ", role)

	some resource_action in role.resource_actions

	resource_action.type == resource_type

	some resource_action_action in resource_action.actions

	resource_action_action == action
}

authz_check(action, org_id, resource_type, resource_id) if {
	allowed_on(
		input.principal_id,
		resource_type,
		action,
		org_id,
		resource_id,
	)
}

authz_check(action, org_id, resource_type, resource_id) := false if {
	not allowed_on(
		input.principal_id,
		resource_type,
		action,
		org_id,
		resource_id,
	)
}

check_results := [
result |
	some to_check in input.checks
	print("to_check ", to_check)
	authz_check_result := authz_check(to_check.action, to_check.organization_id, to_check.resource_type, to_check.resource_id)
	print("authz_check_result ", authz_check_result)
	result := {
		"ok": authz_check_result,
		"check": to_check,
	}
]
