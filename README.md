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
opa run -s .
```

This will run an OPA server that uses data from `data.json` and policies in `main`.

#### Running a query over REST API

This should work as-is using the hard-coded JWT signing certs, using the [REST API](https://www.openpolicyagent.org/docs/latest/rest-api/#execute-a-simple-query)

```sh
❯ curl "0.0.0.0:8181/v1/data/main/rbac/check_results?pretty=true" -d @example/sample_input.json
```

To create a new JWT, use [jwt-cli](https://github.com/mike-engel/jwt-cli) to generate one based on the example in `examples/jwt_claims/json` and the hard-coded private key:

```sh
❯ jwt encode --alg PS512 --secret @rsa2048_private.pem "$(cat example/jwt_claims.json)"
eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9.eyJpYXQiOjE2ODcyNjU4MjgsImlzcyI6ImVsYXN0aWMtaWFtIiwicm9sZV9hc3NpZ25tZW50cyI6W3sib3JnYW5pemF0aW9uX2lkIjoib3JnMTIzIiwicm9sZV9pZCI6InZpZXdlciIsInNjb3BlIjp7ImFsbCI6dHJ1ZX19XSwic3ViIjoidmlld2VyYWxsMTIzIn0.oty2ccdXOiLwSRrb_i9HBY057X8hBmJRe2gAg0YphsmR5JqeDh8pOtN__Cxj66QlEjxMwKc18PUZ_etMqqpjL-YRvhlUAaJoyKh9AtCgjbAN2eET_2SAdyng9eHCpWnqd1G-vWbucuwiFq7UUgV7uNQnwEaoMH4tBU8V0t0emsgZlsBCdLbT5WI2qYAfA7VMjJMPDELVR5fjvv5G21LilHNBMNtO-aVHOniIyvyPrEbb1sLlHGhoQXhcCy3_TTBQsCqgH43YUwbyH1IIFX6yHAG6VQiJTVueD5YR_nqgvvo2AmMKQbsP0bRKROp_jPCQCrdAhJEkmUUQdp9J0BTNRQ
```

Paste that output as `jwt_token` in `example/sample_input.json`, and re-try



### Misc. commands that help

#### (Re)generating keys

```sh
# RSA
openssl genrsa 2048 -out rsa2048_private.pem
openssl rsa -in rsa2048_private.pem -pubout -out rsa2048_public.pem
```

####  Round-tripping JWTs

Install [jwt-cli](https://github.com/mike-engel/jwt-cli)

```sh
jwt encode --alg PS512 --secret @rsa2048_private.pem "$(cat example/viewerall_jwt.json)" | jwt decode --alg PS512 --secret @rsa2048_public.pem -
```