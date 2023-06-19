package main.rbac

import future.keywords

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
role_assignment_scope_matches(assignment_scope, requested_resource_instance) if {
	assignment_scope.all == true
}

# specific resource ids
role_assignment_scope_matches(assignment_scope, requested_resource_instance) if {
	not requested_resource_instance.all
	some assignment_specific_id in assignment_scope.specific_ids
	assignment_specific_id == requested_resource_instance.id
}

# <-- Helper functions
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

# Use if-else because `allowed_on` could result in no output
authz_check(action, org_id, resource_type, resource_instance) if {
	allowed_on(
		input.principal_id,
		resource_type,
		action,
		org_id,
		resource_instance,
	)
} else = false

#     Helper functions -->

check_results := [
result |
	some to_check in input.checks
	print("to_check ", to_check)
	authz_check_result := authz_check(to_check.action, to_check.organization_id, to_check.resource_type, to_check.instance)
	print("authz_check_result ", authz_check_result)
	result := {
		"ok": authz_check_result,
		"check": to_check,
	}
]

default has_all_requested := false

has_all_requested if {
	every result in check_results {
		result.ok
	}
}
