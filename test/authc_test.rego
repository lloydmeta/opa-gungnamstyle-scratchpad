package test

import data.main.authc

import future.keywords

jwk := crypto.x509.parse_rsa_private_key(data.jwt_private_key)

test_verified_jwt_claims_valid if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "12345",
		},
		jwk,
	)
	authc.verified_jwt_claims with input as {"jwt_token": token}
}

test_verified_jwt_claims_invalid_expired if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "mongo-cloud",
			"sub": "12345",
			"exp": 0,
		},
		jwk,
	)
	not authc.verified_jwt_claims with input as {"jwt_token": token}
}

test_verified_jwt_claims_invalid_iss if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "mongo-cloud",
			"sub": "12345",
		},
		jwk,
	)
	not authc.verified_jwt_claims with input as {"jwt_token": token}
}

test_verified_jwt_claims_bogus_token if {
	not authc.verified_jwt_claims with input as {"jwt_token": "bahahaha"}
}

test_authenticated_jwt_claims_valid if {
	token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "12345",
		},
		jwk,
	)
	authc.authenticated_jwt_claims with input as {"jwt_token": token}
}

test_authenticated_jwt_claims_already_invalidated if {
	to_be_invalidated_token := io.jwt.encode_sign(
		{"alg": "RS256", "typ": "JWT"},
		{
			"iss": "elastic-iam",
			"sub": "12345",
		},
		jwk,
	)
	not authc.authenticated_jwt_claims with input as {"jwt_token": to_be_invalidated_token}
		with data.invalidated_unexpired_tokens as [to_be_invalidated_token]
}
