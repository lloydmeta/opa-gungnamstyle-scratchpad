package test

import data.main.rbac
import future.keywords

# This is stored somewhere in real life and sent to the OPA agents

jwk := crypto.x509.parse_rsa_private_key(data.jwt_private_key)

checks := [
	{
		"action": "read",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"id": "es123"},
	},
	{
		"action": "read",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"id": "es456"},
	},
	{
		"action": "read",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"all": true},
	},
	{
		"action": "edit",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"id": "es123"},
	},
	{
		"action": "edit",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"id": "es456"},
	},
	{
		"action": "edit",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"all": true},
	},
	{
		"action": "create",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"id": "es123"},
	},
	{
		"action": "create",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"id": "es456"},
	},
	{
		"action": "create",
		"organization_id": "org123",
		"resource_type": "elasticsearch",
		"instance": {"all": true},
	},
]

test_rbac_with_unrecognised_token if {
	test_input := {
		"jwt_token": "lolerskates",
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to read all

	every should_not_be_ok_result in results {
		false == should_not_be_ok_result.ok
	}
	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_viewer_all_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "viewerall123",
			"role_assignments": [{
				"role_id": "viewer",
				"organization_id": "org123",
				"scope": {"all": true},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to read all
	every should_be_ok_result in array.slice(results, 0, 2) {
		true == should_be_ok_result.ok
	}
	every should_not_be_ok_result in array.slice(results, 3, count(results) + 1) {
		false == should_not_be_ok_result.ok
	}
	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_viewer_all_full_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "viewerall123",
			"role_assignments": [{
				"role_id": "viewer",
				"organization_id": "org123",
				"scope": {"all": true},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": array.slice(checks, 0, 2),
	}
	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}
	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_viewer_specific_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "viewerspecific123",
			"role_assignments": [{
				"role_id": "viewer",
				"organization_id": "org123",
				"scope": {
					"all": false,
					"specific_ids": ["es123"],
				},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to read a specific thing, but no more
	every should_be_ok_result in array.slice(results, 0, 0) {
		true == should_be_ok_result.ok
	}
	every should_not_be_ok_result in array.slice(results, 1, count(results) + 1) {
		false == should_not_be_ok_result.ok
	}

	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_viewer_specific_full_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "viewerspecific123",
			"role_assignments": [{
				"role_id": "viewer",
				"organization_id": "org123",
				"scope": {
					"all": false,
					"specific_ids": ["es123"],
				},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": array.slice(checks, 0, 0),
	}
	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}
	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_viewer_workspace_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "viewerworkspace123",
			"role_assignments": [{
				"role_id": "viewer",
				"organization_id": "org123",
				"scope": {"workspace_id": "workspace_123"},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to read a specific thing, but no more
	every should_be_ok_result in array.slice(results, 0, 0) {
		true == should_be_ok_result.ok
	}
	every should_not_be_ok_result in array.slice(results, 1, count(results) + 1) {
		false == should_not_be_ok_result.ok
	}

	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_viewer_workspace_full_success if {
	should_be_successful_checks := [
	check |
		some idx, check in checks
		idx in {0, 3, 6}
	]
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "viewerworkspace123",
			"role_assignments": [{
				"role_id": "viewer",
				"organization_id": "org123",
				"scope": {"workspace_id": "workspace_123"},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": array.slice(checks, 0, 0),
	}
	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}
	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_editor_all_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "editorall123",
			"role_assignments": [{
				"role_id": "editor",
				"organization_id": "org123",
				"scope": {"all": true},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to read a specific thing, but no more
	every should_be_ok_result in array.slice(results, 0, 5) {
		true == should_be_ok_result.ok
	}
	every should_not_be_ok_result in array.slice(results, 6, count(results) + 1) {
		false == should_not_be_ok_result.ok
	}

	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_editor_all_full_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "editorall123",
			"role_assignments": [{
				"role_id": "editor",
				"organization_id": "org123",
				"scope": {"all": true},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": array.slice(checks, 0, 5),
	}

	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}

	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_editor_specific_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "editorspecific123",
			"role_assignments": [{
				"role_id": "editor",
				"organization_id": "org123",
				"scope": {
					"all": false,
					"specific_ids": ["es123"],
				},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to edit + read a specific thing, but no more
	assert_specific_ok_indices({0, 3}, results)

	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_editor_specific_full_success if {
	should_be_successful_checks := [
	check |
		some idx, check in checks
		idx in {0, 3}
	]

	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "editorspecific123",
			"role_assignments": [{
				"role_id": "editor",
				"organization_id": "org123",
				"scope": {
					"all": false,
					"specific_ids": ["es123"],
				},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": should_be_successful_checks,
	}

	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}
	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_editor_workspace_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "editorworkspace123",
			"role_assignments": [{
				"role_id": "editor",
				"organization_id": "org123",
				"scope": {"workspace_id": "workspace_123"},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to edit + read a specific thing, but no more
	assert_specific_ok_indices({0, 3}, results)

	false == rbac.has_all_requested with input as test_input
}

test_rbac_with_editor_workspace_full_success if {
	should_be_successful_checks := [
	check |
		some idx, check in checks
		idx in {0, 3, 6}
	]
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "editorworkspace123",
			"role_assignments": [{
				"role_id": "editor",
				"organization_id": "org123",
				"scope": {"workspace_id": "workspace_123"},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": array.slice(checks, 0, 0),
	}
	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}
	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_admin_all_full_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "adminall123",
			"role_assignments": [{
				"role_id": "admin",
				"organization_id": "org123",
				"scope": {"all": true},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	every should_be_ok_result in results {
		true == should_be_ok_result.ok
	}

	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_specific_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "adminspecific123",
			"role_assignments": [{
				"role_id": "admin",
				"organization_id": "org123",
				"scope": {
					"all": false,
					"specific_ids": ["es123"],
				},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to admin a specific thing, but no more
	assert_specific_ok_indices({0, 3, 6}, results)
}

test_rbac_with_specific_full_success if {
	should_be_successful_checks := [
	check |
		some idx, check in checks
		idx in {0, 3, 6}
	]
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "adminspecific123",
			"role_assignments": [{
				"role_id": "admin",
				"organization_id": "org123",
				"scope": {
					"all": false,
					"specific_ids": ["es123"],
				},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": should_be_successful_checks,
	}

	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}

	true == rbac.has_all_requested with input as test_input
}

test_rbac_with_admin_workspace_partial_success if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "adminworkspace123",
			"role_assignments": [{
				"role_id": "admin",
				"organization_id": "org123",
				"scope": {"workspace_id": "workspace_123"},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": checks,
	}

	results := rbac.check_results with input as test_input

	# This user has the role assignment to admin a specific thing, but no more
	assert_specific_ok_indices({0, 3, 6}, results)
}

test_rbac_with_admin_workspace_full_success if {
	should_be_successful_checks := [
	check |
		some idx, check in checks
		idx in {0, 3, 6}
	]
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "adminworkspace123",
			"role_assignments": [{
				"role_id": "admin",
				"organization_id": "org123",
				"scope": {"workspace_id": "workspace_123"},
			}],
		},
		jwk,
	)
	test_input := {
		"jwt_token": token,
		"checks": should_be_successful_checks,
	}

	results := rbac.check_results with input as test_input

	every result in results {
		true == result.ok
	}

	true == rbac.has_all_requested with input as test_input
}

assert_specific_ok_indices(expected_ok_idx, results) if {
	every expected_ok_result_idx in expected_ok_idx {
		true == results[expected_ok_result_idx].ok
	}

	expected_not_ok_results := [
	result |
		some idx, result in results
		not idx in expected_ok_idx
	]
	every should_not_be_ok_result in expected_not_ok_results {
		false == should_not_be_ok_result.ok
	}
}
