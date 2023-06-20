package main.authc

import future.keywords

decoding_constraints := data.jwt_constraints

authenticated_jwt_claims := claims if {
	token_already_invalidated := input.jwt_token in data.invalidated_unexpired_tokens
	trace(sprintf("token_already_invalidated [%v], JWT [%v] ", [token_already_invalidated, input.jwt_token]))
	not token_already_invalidated
	claims := verified_jwt_claims
}

verified_jwt_claims := claims if {
	[valid, headers, claims] := io.jwt.decode_verify(input.jwt_token, decoding_constraints)
	trace(sprintf("valid [%v] headers [%v] claims [%v]", [valid, headers, claims]))
	valid
}
