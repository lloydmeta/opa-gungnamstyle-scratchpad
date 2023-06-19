package test

import data.main.rbac
import future.keywords

# This is stored somewhere in real life
principals := [
	{
		"principal_id": "viewerall123",
		"role_assignments": [{
			"role_id": "viewer",
			"organization_id": "org123",
			"scope": {"all": true},
		}],
	},
	{
		"principal_id": "viewerspecific123",
		"role_assignments": [{
			"role_id": "viewer",
			"organization_id": "org123",
			"scope": {"all": false, "specific_ids": ["es123"]},
		}],
	},
	{
		"principal_id": "editorall123",
		"role_assignments": [{
			"role_id": "editor",
			"organization_id": "org123",
			"scope": {"all": true},
		}],
	},
	{
		"principal_id": "admin123",
		"role_assignments": [{
			"role_id": "admin",
			"organization_id": "org123",
			"scope": {
				"all": false,
				"specific_ids": ["es123"],
			},
		}],
	},
]

test_rbac_with_viewer_all if {
	test_input := {
		"principal_id": "viewerall123",
		"checks": [
			{
				"action": "read",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
			{
				"action": "edit",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
			{
				"action": "create",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
		],
	}

	results := rbac.check_results with input as test_input
		with data.principals as principals
	true == results[0].ok
	false == results[1].ok
	false == results[2].ok
}

test_rbac_with_viewer_specific if {
	test_input := {
		"principal_id": "viewerspecific123",
		"checks": [
			{
				"action": "read",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
			{
				"action": "read",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es456",
			},
		],
	}

	results := rbac.check_results with input as test_input
		with data.principals as principals
	true == results[0].ok
	false == results[1].ok
}

test_rbac_with_editor_all if {
	test_input := {
		"principal_id": "editorall123",
		"checks": [
			{
				"action": "read",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
			{
				"action": "edit",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
			{
				"action": "create",
				"organization_id": "org123",
				"resource_type": "elasticsearch",
				"resource_id": "es123",
			},
		],
	}

	results := rbac.check_results with input as test_input
		with data.principals as principals
	true == results[0].ok
	true == results[1].ok
	false == results[2].ok
}
