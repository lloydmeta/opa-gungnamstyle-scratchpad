## OPA Scratchpad

Nothing to see here, just some guy experimenting with OPA for implementing RBAC

### Testing

```sh
 opa test . --explain full
```

### Starting a server

First, [install OPA](https://www.openpolicyagent.org/docs/latest/#running-opa)

Then in the project root dir, run

```sh
opa run -s .
```

This will run an OPA server that uses data from `data.json` and policies in `main`.

#### Running a query over REST API


```sh
❯ curl "0.0.0.0:8181/v1/data/main/rbac/check_results?pretty=true" -d @example/viewerall_input.json
```

### Next steps

Remove the need to distribute the entire list of principals-> role assignments

Instead:
* Centralised service:
  * Distribute store of `invalidated`-yet-not-expired ones to OPAs as `data`
    * Clear out expired ones once an hour
    * This should be _tiny_
  * When issuing a JWT, store the role-assignment data ON The JWT as a custom claim
    * https://www.scottbrady91.com/jose/jwts-which-signing-algorithm-should-i-use
    * ECDSA? since it's supported by one of OPA's built functions
* OPA-side, when accepting `input` with JWT
  * Check for presence in `invalidated` tokens, bail if invalid
  * Decode+verify authc tokens https://www.openpolicyagent.org/docs/latest/policy-reference/#using-pem-encoded-x509-certificate
  * Run authz check based on role-assignment data in JWT claim