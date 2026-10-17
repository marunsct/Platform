# Matura SDK for Go

`github.com/marunsct/Platform/sdk/go` (package `matura`) verifies Matura access tokens, checks permissions, receives
signed webhooks, and keeps the `matura_*` contract tables current in PostgreSQL (contract:
`docs/spec/03-app-integration-contract.md`). It uses the standard library and pgx v5 only, and matches the Python and
TypeScript SDKs feature for feature.

```sh
go get github.com/marunsct/Platform/sdk/go
```

## Verify tokens (net/http)

```go
verifier, err := matura.NewVerifier(matura.VerifierOptions{
	Issuer: "https://id.example.com/realms/matura", Audience: "notes",
})

mux := http.NewServeMux()
auth := matura.Middleware(verifier)
mux.Handle("GET /notes", auth(matura.RequirePermission("note.read")(http.HandlerFunc(listNotes))))
mux.Handle("POST /notes", auth(matura.RequireTenant()(matura.RequirePermission("note.write")(http.HandlerFunc(addNote)))))

func listNotes(w http.ResponseWriter, r *http.Request) {
	p, _ := matura.PrincipalFrom(r.Context()) // UserID, TenantID, WorkspaceID, Roles, Permissions, PlacementMode, …
	…
}
```

Keys come from `<issuer>/protocol/openid-connect/certs` and are cached for 5 minutes; a token signed with an unknown
key fetches them again (at most every 10 seconds), and when the endpoint is down the known keys keep working.
RS256/384/512, PS256 and ES256/384 are accepted; `none` and `HS*` never are. Clock leeway is 30 seconds.

`Middleware` answers 401 problem+json for a missing or bad token; `RequirePermission`, `RequireRole`,
`RequireTenantRole` and `RequireTenant` answer 403. Check permissions (`p.Has("note.write")`, `*` grants all), not
role names. Outside a middleware chain: `matura.Authenticate(ctx, verifier, r)` and `p.RequirePermission(...)`, which
return errors wrapping `ErrInvalidToken` and `ErrForbidden`. When a token carries `perms_ref` instead of `perms`, call
`p.Expand(rolePermissions)` with the permissions per role from `matura_app_role`. The raw claims are in `p.Claims`.

To create the token's tenant, user and membership rows on first sight (just in time, version 0):

```go
contract := matura.NewContract()
auth := matura.Middleware(verifier, matura.OnPrincipal(func(r *http.Request, p *matura.Principal) error {
	return contract.ApplyPrincipal(r.Context(), ownerPool, p)
}))
```

## Create the contract tables

```go
err := contract.Create(ctx, ownerPool, true) // true: shared-mode row-level security
```

`matura.PostgresSQL` and `matura.PostgresSharedRLSSQL` are `docs/contract/sql/postgres.sql` and
`postgres-shared-rls.sql` (the tests check the copies are identical), for your own migration tool. Other databases:
`docs/contract/sql/`.

## Shared mode: scope each transaction to the tenant

```go
err := matura.WithTenant(ctx, appPool, p.TenantID, func(tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT id, title FROM notes`) // RLS limits rows to the tenant
	…
})
// or, inside a handler behind Middleware:
err := matura.WithPrincipalTenant(r.Context(), appPool, func(tx pgx.Tx) error { … })
```

Both run `set_config('matura.tenant_id', $1, true)` at the start of the transaction (`matura.SetTenant` does it in a
transaction you already have). Connect `appPool` as a role that owns nothing and has no `BYPASSRLS`.

## Receive webhooks

```go
mux.Handle("POST /matura/events", matura.NewWebhookHandler(os.Getenv("MATURA_WEBHOOK_SECRET"), contract, ownerPool))

contract.On("matura.placement.provisioned", func(ctx context.Context, db matura.Executor, e *matura.Event) error {
	var p matura.Placement
	if err := e.Decode(&p); err != nil {
		return err
	}
	return migrateTenant(ctx, p) // runs in the event's transaction; an error rolls back and Matura retries
})
```

The handler checks `Matura-Signature` (5 minutes tolerance; any `v1` during a secret rotation, and several secrets in
`WebhookHandler.Secrets`), skips event ids already in `matura_inbox`, applies the change with the version rule and
runs your hooks in one transaction. It answers 204, 401 (bad signature), 400 (not a Matura event) or 500 (database or
hook error, so Matura retries; `OnError` sees it). Hooks are registered by object (`"membership"`), exact type or
`"*"`.

The version rule: a row is kept only when the incoming `version` is newer, so order and duplicates do not matter.
Missing tenants, users and workspaces are created as version-0 stubs, a renamed role renames its grants, and a
placement sets the tenant's `data_mode` under its own version (`placement_version`).

## Apply the change feed

```go
client := matura.NewClient("https://id.example.com", "notes", os.Getenv("MATURA_CLIENT_SECRET"))
sync := &matura.Sync{Client: client, App: "notes", Contract: contract, DB: ownerPool}
n, err := sync.CatchUp(ctx, 0) // at start-up and hourly; snapshots first, and again if the cursor expired (HTTP 410)
```

`client.Changes` and `client.Snapshot` are the raw calls; `matura.SnapshotEvents` turns a snapshot into events.

## Data placement

```go
pl, err := client.Placement(ctx, "notes", tenantID)                            // Mode, Manager, State
cr, err := client.Credentials(ctx, "notes", tenantID, matura.PurposeMigrate)   // platform-managed; keep in memory
pl, err = client.RegisterPlacement(ctx, "notes", tenantID, matura.StorageRegistration{
	LocationLabel: "eu-1", DatabaseName: "notes_acme"})                       // storage the app created
pl, err = client.PlacementReady(ctx, "notes", tenantID)                        // after migrating
pl, err = client.PlacementDeleted(ctx, "notes", tenantID)                      // after deleting a retiring tenant's data
```

## Testing with maturatest

```go
iss, _ := maturatest.NewIssuer("", "notes")
verifier := iss.Verifier() // trusts iss, no network
token, _ := iss.Token(maturatest.TokenOptions{TenantID: tid, Perms: []string{"note.read"}})

body, header, _ := maturatest.SignedEvent([]byte("whsec_test"), event, time.Time{})
```

## Developing

```sh
cd sdk/go
export MATURA_TEST_DATABASE_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable'  # a superuser
go vet ./... && go test -race ./...
```

The tests run `docs/contract/test-vectors.json` (signatures, tokens, and the apply sequence against PostgreSQL).
Each database test creates and drops its own database; without the variable those tests are skipped.
