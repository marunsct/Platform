# @matura/sdk

The Matura SDK for TypeScript and Node.js 20+. It verifies Matura access tokens, checks permissions, receives signed
webhooks, and keeps the `matura_*` contract tables current (contract: `docs/spec/03-app-integration-contract.md`).
It has no runtime dependencies: it uses `node:crypto` and the global `fetch`.

```sh
npm install @matura/sdk
```

## Verify a token (Express)

```ts
import express from "express";
import { Verifier, authenticate, requirePermission, InvalidToken, Forbidden } from "@matura/sdk";

const verifier = new Verifier({ issuer: "https://id.example.com/realms/matura", audience: "notes" });
const app = express();

app.post("/notes", async (req, res, next) => {
  try {
    const p = requirePermission(await authenticate(verifier, req.headers), "note.write");
    res.json({ tenant: p.tenantId, user: p.userId });
  } catch (err) {
    if (err instanceof InvalidToken || err instanceof Forbidden) return res.status(err.status).json({ detail: err.message });
    next(err);
  }
});
```

Keys come from `${issuer}/protocol/openid-connect/certs` and are cached for 5 minutes; a token signed with a new key
fetches them again. RS256/384/512, PS256 and ES256/384 are accepted; `none` and `HS*` never are. Check permissions
(`p.has("note.write")`, `*` grants all), not role names. When a token carries `perms_ref` instead of `perms`, call
`p.expand(rolePermissions)` with the permissions per role from `matura_app_role`.

## Create the contract tables

```ts
import { Contract, ddl } from "@matura/sdk";

const contract = new Contract("postgresql"); // or "sqlite"
for (const sql of ddl("postgresql", { rls: true })) await pool.query(sql); // rls: shared mode only
```

The SQL is the same as `docs/contract/sql/` (MySQL and SQL Server files live there too). The SDK talks to the
database through an executor: `{ query(sql, params) => Promise<{ rowCount, rows? }> }` with `$1, $2…` placeholders
for PostgreSQL and `?` for SQLite. A node-postgres `PoolClient` fits as is. You own the transaction.

## Receive webhooks

```ts
import { webhookHandler } from "@matura/sdk";

const handle = webhookHandler({
  secret: process.env.MATURA_WEBHOOK_SECRET!,
  contract,
  transaction: async (fn) => {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (err) {
      await c.query("ROLLBACK");
      throw err;
    } finally {
      c.release();
    }
  },
});

// the raw body is needed to check the signature
app.post("/matura/events", express.raw({ type: "*/*" }), async (req, res) => {
  const { status, body } = await handle(req.body, req.headers);
  res.status(status).type("json").send(body);
});

contract.on("matura.placement.provisioned", async (db, event) => { /* run migrations for the tenant */ });
```

The handler checks `Matura-Signature` (5 minutes tolerance, any `v1` during a secret rotation), skips event ids
already in `matura_inbox`, applies the change with the version rule and runs your hooks in the same transaction. It
answers 204, 401 (bad signature) or 400 (not a Matura event); database errors are thrown so Matura retries.

## Apply the change feed

```ts
import { MaturaAPI, Sync } from "@matura/sdk";

const api = new MaturaAPI({ baseUrl: "https://id.example.com", clientId: "notes", clientSecret: process.env.MATURA_CLIENT_SECRET! });
const sync = new Sync({ api, app: "notes", contract, transaction });
await sync.catchUp(); // at start-up and hourly; takes a snapshot first, and again if the cursor expired (HTTP 410)
```

## Data placement

```ts
const placement = await api.placement("notes", tenantId);              // mode, manager, state
const creds = await api.credentials("notes", tenantId, "migrate");     // platform-managed storage; keep in memory
await api.registerPlacement("notes", tenantId, { locationLabel: "eu-1", databaseName: "notes_acme" }); // own storage
await api.placementReady("notes", tenantId);                           // after migrating
await api.placementDeleted("notes", tenantId);                         // after deleting a retiring tenant's data
```

## Resource permissions (OpenFGA)

With an authorization model in the manifest (contract §11); maturad answers 501 when it runs without OpenFGA.

```ts
await api.writeRelations("notes", tenantId, { writes: [{ user: `user:${p.userId}`, relation: "owner", object: `document:${id}` }] });
const ok = await api.check("notes", tenantId, `user:${p.userId}`, "editor", `document:${id}`);
const results = await api.batchCheck("notes", tenantId, checks, { fresh: true });  // up to 50, in order
const docs = await api.listObjects("notes", tenantId, `user:${p.userId}`, "viewer", "document");
```

## Testing with FakeIssuer

```ts
import { FakeIssuer, Verifier, signedEvent } from "@matura/sdk";

const issuer = new FakeIssuer({ audience: "notes" });
const verifier = new Verifier({ issuer: issuer.issuer, audience: "notes", jwks: issuer.jwks });
const token = issuer.token({ tenantId: "0192…", perms: ["note.read"] });

const { body, headers } = signedEvent("whsec_test", { id: "evt_1", type: "matura.tenant.created", data: { /* … */ } });
```

## Developing

```sh
npm install
npm run build      # tsc → dist/ with declarations
npm test           # compiles src and test to build-test/, runs node:test (includes docs/contract/test-vectors.json)
npm run typecheck
```

The tests use `node:sqlite` (Node 22.5+), which prints an experimental warning.
