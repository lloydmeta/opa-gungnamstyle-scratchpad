package test

import data.main.workspaces

import future.keywords

test_resource_id_to_workspaces_set if {
	workspaces_def := {
		"workspace1": {
			"organization_id": "org123",
			"resource_ids": ["resource_123", "resource_456"],
		},
		"workspace2": {
			"organization_id": "org123",
			"resource_ids": ["resource_123"],
		},
		"workspace3": {
			"organization_id": "org456",
			"resource_ids": ["resource_789"],
		},
	}
	resolved_set := workspaces.resource_id_to_workspaces_set with data.workspaces as workspaces_def
	resolved_set.resource_123 = {
		"workspace1",
		"workspace2",
	}
	resolved_set.resource_456 = {"workspace1"}
	resolved_set.resource_789 = {"workspace3"}
	not "resource_rando1231" in resolved_set
}
