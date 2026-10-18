# Conformance kit: prove your app follows the contract

`matura-conformance` checks a running app from the outside, whatever language it is written in
([contract §10.4](../spec/03-app-integration-contract.md#104-proving-it-the-conformance-kit)). It plays Matura: it
runs a test token issuer, mints tokens shaped exactly like Matura's for two random tenants, sends signed events, and
calls your app's own API to see whether it keeps tenants apart and refuses what it should.

## What it checks

| Group | Check | Expected |
|---|---|---|
| seed | signed `matura.tenant.created`, `matura.workspace.created`, `matura.user.updated`, `matura.membership.added`, `matura.grant.added` for tenants A and B (increasing versions) | 2xx, so apps with contract tables know the test users |
| authentication | each resource's list endpoint with a valid token | 2xx |
| | … without a token, with an expired token, a token for another audience, a token signed by an unknown key, a token from another issuer | 401 |
| permissions | create and list with a valid token whose `perms` lack the endpoint's permission | 403 |
| isolation | A creates a record carrying a unique marker | 2xx |
| | A's list contains the marker; B's list does not | 2xx, marker present / absent |
| | A reads the record by id; B reads it by id (when `read` is given) | 2xx; 403 or 404 |
| events | a validly signed event; the same event again | 2xx (the repeat must not be applied twice) |
| | a changed body with the old signature; a timestamp 10 minutes old; another secret; no signature | 4xx |

Seed and event checks run only when the manifest has a `webhook_path`. Tokens carry `iss`, `aud`, `azp`, `sub`,
`iat`, `exp`, `email`, `email_verified`, `name`, `tid`, `tenant`, `wid`, `troles`, `roles`, `perms`, `ver` and
`pmode` (contract §2); `perms` lists every permission the manifest names, so the app must not need `"*"`.

## Running it

```sh
go build ./cmd/matura-conformance
matura-conformance --app http://localhost:8000 --manifest matura/manifest.json --webhook-secret whsec_dev
```

It starts the issuer first and prints how to start your app:

```
MATURA_ISSUER=http://127.0.0.1:8099/realms/conformance MATURA_AUDIENCE=notes MATURA_WEBHOOK_SECRET=whsec_dev
```

Point your app at that issuer (its JWKS is at `<issuer>/protocol/openid-connect/certs`, discovery at
`<issuer>/.well-known/openid-configuration`), audience and webhook secret, and start it. The checker waits up to
`--wait` (default 30s) for the app URL to answer, then runs. The issuer's address is stable (`--issuer-addr`,
default `127.0.0.1:8099`) but its key is new on every run, so the app must fetch the JWKS rather than pin a key. Pass
`--webhook-secret` to keep the secret stable too; otherwise a new one is generated each run.

| Flag | Default | |
|---|---|---|
| `--app` | required | base URL of the running app |
| `--manifest` | required | the app manifest (JSON, or YAML for `.yaml`/`.yml`) |
| `--issuer-addr` | `127.0.0.1:8099` | where the test issuer listens |
| `--webhook-secret` | generated | the secret the app verifies `Matura-Signature` with |
| `--audience` | manifest `client_id`, else `slug` | the `aud` the app expects |
| `--wait` | `30s` | how long to wait for the app to answer |
| `--json` | off | machine-readable report on stdout (instructions go to stderr) |

The records it creates stay in your app under two throw-away tenants (`conformance-a-…`, `conformance-b-…`); run it
against a development database.

## The manifest's `conformance` section

```json
"conformance": {
  "webhook_path": "/matura/events",
  "resources": [{
    "name": "notes",
    "create": {"method": "POST", "path": "/api/notes", "body": {"title": "conformance {{marker}}"}, "permission": "note.write"},
    "list":   {"method": "GET",  "path": "/api/notes", "permission": "note.read"},
    "read":   {"method": "GET",  "path": "/api/notes/{id}", "permission": "note.read"}
  }]
}
```

- `webhook_path`: where the app receives Matura webhooks. Leave it out to skip seed and event checks.
- `resources`: one entry per kind of tenant-owned record. `create` and `list` are required, `read` is optional.
- `{{marker}}` in a create path or body becomes a unique string; the list response must echo it somewhere for
  tenant A and nowhere for tenant B, so put it in a field the list returns.
- The record id is read from the create response's `id`, or `data.id` (string or number), and replaces `{id}` in
  the read path.
- `method` defaults to `POST` for create and `GET` for list and read. `permission` is what the endpoint requires;
  without it the permission check for that endpoint is skipped.

## Reading the report

One line per check: status, group, what was sent and what was expected, and why:

```
PASS  authentication notes list (GET /api/notes) with an expired token → 401: got 401
FAIL  isolation      tenant B's notes list does not contain A's record: got 200, but the response contains tenant A's marker: data leaks across tenants
SKIP  isolation      tenant A's notes list contains A's record: tenant A could not create a record

FAILED: 18 passed, 1 failed, 2 skipped
```

`SKIP` means a check could not run (no webhook path, no permission given, or an earlier step failed); skips alone do
not fail the run. The exit code is 0 when no check failed and 1 otherwise (2 for bad flags or manifest). With
`--json` the report is `{"app", "issuer", "audience", "ok", "passed", "failed", "skipped", "checks": [{"id",
"group", "title", "status", "reason"}]}`; check ids such as `auth/notes/expired` or `isolation/notes/list-other` are
stable, so CI can assert on them.
