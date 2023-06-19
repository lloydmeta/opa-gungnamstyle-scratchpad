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