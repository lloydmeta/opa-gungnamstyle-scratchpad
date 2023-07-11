## OPA Scratchpad [![Run OPA Tests](https://github.com/lloydmeta/opa-gungnamstyle-scratchpad/actions/workflows/ci.yml/badge.svg)](https://github.com/lloydmeta/opa-gungnamstyle-scratchpad/actions/workflows/ci.yml)

Nothing to see here, just some guy experimenting with OPA for implementing RBAC

### Testing

```sh
 opa test . --explain full
```

### Starting a server

First, [install OPA](https://www.openpolicyagent.org/docs/latest/#running-opa)

Then in the project root dir, run

```sh
# Run in server mode, and watch local changes
opa run -s -w .
```

This will run an OPA server that uses data from `data.json` and policies in `main`.

#### Running a query over REST API

This should work as-is using the hard-coded JWT signing certs, using the [REST API](https://www.openpolicyagent.org/docs/latest/rest-api/#execute-a-simple-query)

```sh
curl "0.0.0.0:8181/v1/data/main/rbac/check_results?pretty=true" -d @example/sample_input.json
```

To create a new JWT where the role assignments are different (e.g. instead of a viewer assignment scoped to all deployments, an admin, or workspace), modify `example/jwt_claims.json` to be:

```json
{
  "sub": "viewerall123",
  "iss": "elastic-iam",
  "role_assignments": [
    {
      "role_id": "viewer",
      "organization_id": "org123",
      "scope": {
        "specific_ids": [
          "es123"
        ]
      }
    }
  ]
}
```

Then, use [jwt-cli](https://github.com/mike-engel/jwt-cli) to generate a JWT signed with the hard-coded private key:

```sh
jwt encode --alg PS512 --secret @rsa2048_private.pem "$(cat example/jwt_claims.json)"

# Output
eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJpYXQiOjE2ODc4NzM3ODUsImlzcyI6ImVsYXN0aWMtaWFtIiwicm9sZV9hc3NpZ25tZW50cyI6W3sib3JnYW5pemF0aW9uX2lkIjoib3JnMTIzIiwicm9sZV9pZCI6InZpZXdlciIsInNjb3BlIjp7InNwZWNpZmljX2lkcyI6WyJlczEyMyJdfX1dLCJzdWIiOiJ2aWV3ZXJhbGwxMjMifQ.ZK_x5iermcmIlPiK-evNo7wn4Xp4eEx54QZbjnIbFD5ehDPgto1_R9CawLQT4RQ7sPcx2Ql7iGrnv6vV5BukNRhUqNjY4Q_-wlPB2T3KWA6qQb4ELZ6-bGTAOqqIGD1J7vNi29M24Ow9Jb9YYwfedjR4td2HEpnWnzCqU97erUJAmHknt2PUFxtm1ybbe93B65Xpqk8SSyvaJlbG8utxEwpfYSe-ThHrHbCT1uJnTfzmYauJAIdxgk6Xvx3b-e6zhWraKqgpbn_LD2bRatQG_wol-zcT_r92fh-YlhSFlVDztndLdiJfttd8AOqDLRZE_zC21hkndNWuRjJIPo9-tQ
```

Paste that output as `jwt_token` in `example/sample_input.json`, and re-try the curl.

### Misc. Things that help

#### (Re)generating keys

```sh
# RSA
openssl genrsa 2048 -out rsa2048_private.pem
openssl rsa -in rsa2048_private.pem -pubout -out rsa2048_public.pem
```

####  Round-tripping JWTs

Install [jwt-cli](https://github.com/mike-engel/jwt-cli)

```sh
jwt encode --alg PS512 --secret @rsa2048_private.pem "$(cat example/jwt_claims.json)" | jwt decode --alg PS512 --ignore-exp --secret @rsa2048_public.pem -
```

#### Different scenarios

##### Workspace

Tweak `data.json` to modify workspace definitions (if run with `-w`, the changes will auto-reload)

Update `jwt_claims.json` to be

```json
{
  "sub": "viewerworkspace123",
  "iss": "elastic-iam",
  "role_assignments": [
    {
      "role_id": "viewer",
      "organization_id": "org123",
      "scope": {
        "workspace_id": "workspace_123"
      }
    }
  ]
}
```

Generate the JWT, put it in `sample_input.json` and re-run the curl.