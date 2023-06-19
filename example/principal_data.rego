package example

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
			"scope": {
				"all": false,
				"specific_ids": ["es123"],
			},
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
		"principal_id": "editorspecific123",
		"role_assignments": [{
			"role_id": "editor",
			"organization_id": "org123",
			"scope": {
				"all": false,
				"specific_ids": ["es123"],
			},
		}],
	},
	{
		"principal_id": "adminall123",
		"role_assignments": [{
			"role_id": "admin",
			"organization_id": "org123",
			"scope": {"all": true},
		}],
	},
	{
		"principal_id": "adminspecific123",
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
