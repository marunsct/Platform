# App integration contract — how user information reaches an app

*Version 0.1 · 2026-10-16 · proposed. Every app on Matura (DevFlow, AgentCanvas, any other) follows this contract.
Decisions: [ADR 0006](../adr/0006-data-placement-modes.md), [ADR 0007](../adr/0007-app-contract-tables.md).*

## 1. Overview

User information reaches an app through three channels, and lands in the same tables in every app:

```
              ┌─────────── Matura ────────────┐
              │  Keycloak        maturad      │
              │  (tokens)     (outbox, feed)  │
              └───┬──────────────┬───────┬────┘
   1. token on    │   2. signed  │       │ 3. change feed
   every request  │   events     │       │    (pull from cursor)
                  ▼              ▼       ▼
              ┌────────────── the app ──────────────┐
              │ Matura SDK                           │
              │  verify → Principal → upsert ──┐     │
              │  event receiver ───────────────┼──► matura_* contract tables
              │  feed reader (start-up, hourly)┘     │      ▲
              │                                      │      │ foreign keys
              │  app code ──► its own tables (tenant_id, workspace_id, created_by)
              └──────────────────────────────────────┘
```

| Channel | Carries | When | Why |
|---|---|---|---|
| Access token | the caller: user, tenant, workspace, roles, versions | every request | authorisation without calling Matura |
| Events (webhook, later NATS) | every change to tenants, workspaces, users, memberships, grants, placements | within seconds of the change | the app learns about people who are not signed in, and about removals |
| Change feed | the same changes, from a cursor; or a full snapshot | start-up, hourly, after errors | repairs anything an event missed |

All three write through one SDK function, `apply(change)`, which keeps a row only if its `version` is newer than
the stored one. Order and duplicates therefore do not matter.

## 2. The access token

Issued by Keycloak with the Matura mapper (TS5). JWT, ES256 or RS256, 5-minute lifetime, under 2 KB.

| Claim | Type | Meaning |
|---|---|---|
| `iss` | string | `https://<matura-host>/realms/matura` |
| `aud` | string | the app's client id, e.g. `devflow` |
| `sub` | uuid | Matura user id (same as the Keycloak user id) |
| `email`, `email_verified`, `name`, `locale` | | profile basics |
| `tid` | uuid | tenant the token is for (absent only before the user has any tenant) |
| `tenant` | string | tenant slug, for URLs and logs |
| `wid` | uuid | current workspace, when the app is workspace-scoped |
| `troles` | string[] | tenant role, e.g. `["admin"]` |
| `roles` | string[] | this app's roles in this tenant and workspace, e.g. `["operator"]` |
| `perms` | string[] | the permissions those roles give in this app, expanded by Matura, e.g. `["run.read","run.start"]`; `["*"]` for full access |
| `perms_ref` | string | instead of `perms` when they would exceed 40 entries: read them from `matura_app_role` for `roles` |
| `ver` | object | `{"u": 12, "m": 40, "t": 7}`: versions of the user, membership and tenant rows that produced the token |
| `pmode` | string | placement mode for this app and tenant: `shared`, `schema` or `database` (routing hint; the SDK still checks its placement cache) |
| `acr`, `amr` | | MFA level and methods |
| `sid` | string | session id, for back-channel logout |
| `azp`, `client_id` | | for machine tokens; `sub` is then the service account |

Roles are defined and edited in Matura (ADR 0008), so the app does not know which permissions a role gives:
Matura expands them into `perms`. An app checks `perms` and never needs role names, which is what makes a check
possible in any language with only a JWT library (ADR 0009).

Example:

```json
{
  "iss": "https://id.example.com/realms/matura", "aud": "devflow",
  "sub": "0192b7a4-5c1e-7d2a-9f00-4b1e2a9c0d11", "email": "ana@acme.com", "email_verified": true,
  "name": "Ana Silva", "tid": "0192b7a4-6000-7000-8000-00000000acme", "tenant": "acme",
  "wid": "0192b7a4-6001-7000-8000-0000000000w1", "troles": ["member"], "roles": ["operator"], "perms": ["run.read", "run.start"],
  "ver": {"u": 12, "m": 40, "t": 7}, "pmode": "shared", "acr": "1", "sid": "f3a…", "exp": 1792140300
}
```

## 3. Contract tables

Created by the SDK's migration (`matura.contract.v1`, shipped as an Alembic operation, a plain SQL file and, later,
Prisma and Goose files). Only the SDK writes to them; the app reads and references them.

Where they live:

| Mode | Contract tables are in | Holding |
|---|---|---|
| `shared` | the app's shared database, schema `public` (or the app's schema) | rows of every tenant; RLS on each table |
| `schema` | each tenant's schema | that tenant's rows only, plus the users who are its members |
| `database` | each tenant's database | that tenant's rows only, plus the users who are its members |

Identical DDL in every mode; only the RLS policies are skipped where the schema or database already isolates.

```sql
-- matura.contract.v1  (PostgreSQL 14+)

CREATE TABLE matura_tenant (
    id           uuid PRIMARY KEY,                 -- token claim tid
    slug         text NOT NULL UNIQUE,
    name         text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('company','shared','personal')),
    status       text NOT NULL CHECK (status IN ('provisioning','active','suspended','deleting','deleted')),
    plan         text,
    data_mode    text NOT NULL CHECK (data_mode IN ('shared','schema','database')),  -- this app's placement mode
    version      bigint NOT NULL,
    updated_at   timestamptz NOT NULL,
    placement_version bigint NOT NULL DEFAULT 0   -- version of the placement change data_mode came from; 0 = none yet
);

CREATE TABLE matura_workspace (
    id           uuid PRIMARY KEY,                 -- token claim wid
    tenant_id    uuid NOT NULL REFERENCES matura_tenant(id),
    name         text NOT NULL,
    status       text NOT NULL CHECK (status IN ('active','archived','deleted')),
    is_default   boolean NOT NULL DEFAULT false,
    version      bigint NOT NULL,
    updated_at   timestamptz NOT NULL,
    UNIQUE (tenant_id, id)                         -- target for composite foreign keys
);

CREATE TABLE matura_user (
    id             uuid PRIMARY KEY,               -- token claim sub
    email          text,                           -- NULL after deletion
    email_verified boolean NOT NULL DEFAULT false,
    display_name   text,
    avatar_url     text,
    locale         text,
    kind           text NOT NULL DEFAULT 'human' CHECK (kind IN ('human','service','agent')),
    status         text NOT NULL CHECK (status IN ('active','deactivated','deleted')),
    version        bigint NOT NULL,
    updated_at     timestamptz NOT NULL
);

CREATE TABLE matura_membership (
    tenant_id    uuid NOT NULL REFERENCES matura_tenant(id),
    user_id      uuid NOT NULL REFERENCES matura_user(id),
    tenant_role  text NOT NULL CHECK (tenant_role IN ('owner','admin','billing','member')),
    status       text NOT NULL CHECK (status IN ('active','deactivated','removed')),
    joined_at    timestamptz NOT NULL,
    version      bigint NOT NULL,
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE matura_role_grant (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES matura_tenant(id),
    workspace_id uuid,                             -- NULL = whole tenant
    subject_type text NOT NULL CHECK (subject_type IN ('user','group','service_account')),
    subject_id   uuid NOT NULL,
    role         text NOT NULL,                    -- one of this app's roles (matura_app_role.name)
    status       text NOT NULL CHECK (status IN ('active','revoked')),
    version      bigint NOT NULL,
    updated_at   timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace(tenant_id, id)
);
CREATE INDEX matura_role_grant_subject ON matura_role_grant (tenant_id, subject_id) WHERE status = 'active';

CREATE TABLE matura_app_role (                     -- this app's roles as defined in Matura (not tenant-owned)
    name         text PRIMARY KEY,
    description  text,
    permissions  text[] NOT NULL,                  -- from the app's permission catalogue, or '{*}'
    is_default   boolean NOT NULL DEFAULT false,
    status       text NOT NULL CHECK (status IN ('active','deleted')),
    version      bigint NOT NULL,
    updated_at   timestamptz NOT NULL
);

-- bookkeeping
CREATE TABLE matura_sync_cursor (
    stream       text PRIMARY KEY,                 -- 'changes' (shared mode) or 'changes:<tenant>' 
    cursor       text NOT NULL,
    synced_at    timestamptz NOT NULL
);
CREATE TABLE matura_inbox (                        -- processed event ids, for idempotency; pruned after 7 days
    event_id     text PRIMARY KEY,
    received_at  timestamptz NOT NULL
);
CREATE TABLE matura_contract (                     -- which contract version this database has
    version      text PRIMARY KEY,
    applied_at   timestamptz NOT NULL
);
```

Row-level security on contract tables in `shared` mode (the SDK migration adds it):

```sql
ALTER TABLE matura_workspace  ENABLE ROW LEVEL SECURITY; ALTER TABLE matura_workspace  FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON matura_workspace
  USING (tenant_id = current_setting('matura.tenant_id', true)::uuid);
-- same policy on matura_membership and matura_role_grant;
-- matura_tenant: USING (id = current_setting('matura.tenant_id', true)::uuid)
-- matura_user:   USING (EXISTS (SELECT 1 FROM matura_membership m
--                               WHERE m.user_id = matura_user.id
--                                 AND m.tenant_id = current_setting('matura.tenant_id', true)::uuid))
-- The SDK's sync writer runs as the app's owner role (no RLS) because it writes rows for every tenant.
```

Deleted users keep their `id` row with `email`, `display_name` and `avatar_url` set to NULL and `status = 'deleted'`,
so the app's foreign keys stay valid and the UI shows "deleted user".

## 4. Rules for the app's own tables

1. Every tenant-owned table has `tenant_id uuid NOT NULL REFERENCES matura_tenant(id)`, and
   `workspace_id uuid NOT NULL` with `FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace(tenant_id, id)`
   when the app is workspace-scoped. Keep them in `schema` and `database` modes too, so data can move between modes.
2. Child rows reference parents with composite keys `(tenant_id, parent_id)`, so a child can never point into another
   tenant.
3. Columns naming a person reference `matura_user(id)`: `created_by`, `updated_by`, `assigned_to`.
4. In `shared` mode each table gets `ENABLE` and `FORCE ROW LEVEL SECURITY` and the policy
   `USING (tenant_id = current_setting('matura.tenant_id', true)::uuid)`. The SDK's Alembic helper
   `op.matura_tenant_table("runs")` adds columns, keys, index and policy; `matura lint-db` fails CI if a table lacks them.
5. Indexes lead with `tenant_id` (and `workspace_id`).
6. Never add columns to `matura_*` tables; app-specific user data goes in the app's own table keyed by `user_id`
   (e.g. `devflow_user_settings(tenant_id, user_id, …)`).
7. The app connects as a role without `BYPASSRLS` that owns nothing; migrations run as the owner role.

## 5. Applying changes

Every change, from any channel, is the same envelope:

```json
{
  "specversion": "1.0", "id": "evt_0192b7…", "source": "matura://installation/main",
  "type": "matura.membership.updated", "time": "2026-10-16T09:12:03Z",
  "subject": "tenants/0192…acme/members/0192…ana",
  "tenantid": "0192…acme", "datacontenttype": "application/json",
  "data": { "object": "membership", "version": 41,
            "membership": { "tenant_id": "…", "user_id": "…", "tenant_role": "admin", "status": "active",
                            "joined_at": "…", "updated_at": "…" } }
}
```

The SDK's `apply`:

```sql
INSERT INTO matura_membership AS m (…, version, updated_at) VALUES (…)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET … = EXCLUDED.…
WHERE m.version < EXCLUDED.version;
```

A placement (`matura.placement.*`) sets `matura_tenant.data_mode` to its `mode` under the same rule, compared with
`placement_version` rather than `version`, because a placement and its tenant change independently. Once a placement
has been applied, tenant changes keep `data_mode` (their `data_mode_default` is only the tenant's default). The SQL is
in `docs/contract/sql/README.md`.

From the token, the SDK upserts the user, tenant and membership only when the token's `ver` is newer than what it has
cached (an in-process cache keyed by user and tenant, so most requests do no database write). Token claims carry
fewer fields than events; a token-created row is completed by the next event or feed read.

## 6. Events

Delivered as signed webhooks (TS7c) and, from M5, NATS subjects `matura.<tenant>.<type>`.

| Type | Sent when |
|---|---|
| `matura.tenant.created`, `.updated`, `.suspended`, `.reactivated`, `.deleting`, `.deleted` | tenant lifecycle; a tenant waiting out its deletion grace period arrives as `suspended` with `purge_after` set (it can still be restored: keep its data until `.deleting`) |
| `matura.workspace.created`, `.updated`, `.archived`, `.deleted` | workspaces |
| `matura.user.created`, `.updated`, `.deactivated`, `.deleted` | profile changes (sent to every app the user's tenants use) |
| `matura.membership.added`, `.updated`, `.removed` | members |
| `matura.tenant_app.enabled`, `.disabled` | the tenant turned this app on or off |
| `matura.grant.added`, `.revoked` | app role grants (only this app's) |
| `matura.placement.requested`, `.provisioned`, `.ready`, `.moving`, `.retiring`, `.deleted` | data placements (doc 02 §7) |
| `matura.app.manifest.updated` | the app's manifest (permission catalogue, settings) changed |
| `matura.app.role.created`, `.updated`, `.deleted` | a role was created or edited in Matura; the app updates `matura_app_role`, and new tokens carry the new `perms` |

Webhook headers: `Matura-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">`, `Matura-Event-Id`. The receiver
rejects signatures older than 5 minutes, records `id` in `matura_inbox`, applies, answers 2xx. Matura retries with
exponential backoff for 24 hours, then marks the endpoint failing; the change feed covers the gap.

Apps confirm work that Matura waits for (placement ready, tenant data deleted) by calling the API, not by the
webhook response.

## 7. Change feed

`GET /v1/apps/{app}/changes?cursor=<opaque>&limit=500` with a client-credentials token. Returns changes in commit
order across all tenants that use the app, and `next_cursor`. `GET /v1/apps/{app}/snapshot?tenant=<id>` returns the
current state for bootstrap. In `schema` and `database` modes the SDK reads the feed once and writes each change to
the right tenant's storage; cursors are kept per tenant.

## 8. What the SDK gives the app (optional)

The SDKs are shortcuts over §2–§7; §10 shows the same steps without one.

```python
from matura import Matura, Principal, require_permission

matura = Matura.from_env()               # MATURA_ISSUER, MATURA_CLIENT_ID, MATURA_CLIENT_SECRET, MATURA_API
app.add_middleware(matura.fastapi_middleware())

@app.get("/runs")
async def list_runs(p: Principal = Depends(require_permission("run.read")),
                    db: AsyncSession = Depends(matura.tenant_session)):   # routed + scoped to p.tenant_id
    return (await db.execute(select(Run))).scalars().all()               # RLS limits rows in shared mode

app.include_router(matura.webhook_router())   # POST /matura/events
matura.on("placement.provisioned", run_migrations_for_tenant)
```

`Principal`: `user_id`, `tenant_id`, `tenant_slug`, `workspace_id`, `tenant_roles`, `roles`, `permissions`,
`mfa`, `session_id`, `is_service`. Helpers: `require_role`, `require_permission`, `require_tenant_role`,
`require_mfa`.

## 9. Adopting the contract in an existing app

| App | Today | With the contract |
|---|---|---|
| DevFlow | `users` table, own HS256 tokens, roles `admin`/`operator`, no tenants | `matura_*` tables; DevFlow's tables gain `tenant_id`; roles `admin`, `operator`, `viewer` in its manifest; old login kept behind a flag for one release |
| AgentCanvas | `organization`, `app_user`, `membership`, own OIDC verifier | `organization` becomes a view over `matura_tenant` (or its id maps 1:1); `app_user` → `matura_user`; membership roles move to grants; its `org_id` columns become `tenant_id`; its own verifier replaced by the SDK |

## 10. Any language or framework

Everything above is plain OIDC, JWT, SQL, HTTPS and CloudEvents (ADR 0009). An app picks the level it needs; each
level works without a Matura SDK.

| Level | What the app does | What it needs |
|---|---|---|
| **0 Gateway** | nothing in code: `matura-gateway` (an identity-aware reverse proxy) signs users in and forwards `X-Matura-User`, `X-Matura-Tenant`, `X-Matura-Roles`, `X-Matura-Perms` and the token | the gateway in front of the app; the app trusts only the gateway |
| **1 Sign-in** | sign users in with OIDC; verify the access token; read `sub`, `tid`, `wid`, `perms`; refuse requests without the needed permission | any OIDC client and JWT library |
| **2 Directory** | run the contract SQL file; receive signed events at one URL; read the change feed at start-up and hourly; upsert by `version` | its migration tool, an HTTP endpoint, an HTTP client |
| **3 Data placement** | ask for its placement and credentials per tenant; route connections; run migrations on `placement.provisioned`; confirm ready and deleted | the placement API; in shared mode, one `set_config` per transaction |

### 10.1 The same check in four stacks (level 1)

```js
// Node / Express with jose
const { payload } = await jwtVerify(token, jwks, { issuer: ISSUER, audience: "devflow" });
if (!payload.perms.includes("run.start") && !payload.perms.includes("*")) return res.sendStatus(403);
req.tenantId = payload.tid;
```

```java
// Java / Spring Security resource server: issuer-uri set in application.yml
@PreAuthorize("@perms.has(authentication, 'run.start')")
@PostMapping("/runs") Run start(@AuthenticationPrincipal Jwt jwt) { return runs.start(jwt.getClaimAsString("tid")); }
```

```csharp
// ASP.NET Core: AddJwtBearer(o => { o.Authority = Issuer; o.Audience = "devflow"; })
options.AddPolicy("run.start", p => p.RequireAssertion(c =>
    c.User.FindAll("perms").Any(x => x.Value is "run.start" or "*")));
```

```go
// Go net/http with github.com/MicahParks/keyfunc and golang-jwt
tok, err := jwt.ParseWithClaims(raw, &c, jwks.Keyfunc, jwt.WithIssuer(issuer), jwt.WithAudience("devflow"))
if err != nil || !(slices.Contains(c.Perms, "run.start") || slices.Contains(c.Perms, "*")) { w.WriteHeader(403); return }
```

### 10.2 Verifying an event (level 2), any language

1. Read `Matura-Signature: t=<unix>,v1=<hex>` and the raw request body.
2. Refuse if `t` is more than 300 seconds from now.
3. Compute `hex(HMAC-SHA256(secret, t + "." + body))` and compare with `v1` in constant time.
4. Skip if `Matura-Event-Id` is already in `matura_inbox`; otherwise apply the change with the version rule (§5) and
   record the id, in one transaction.

`docs/contract/test-vectors.json` (TS7e) holds signed sample events and sample tokens, so each implementation can be
tested without a running Matura.

### 10.3 What ships for each language

| Stack | Provided |
|---|---|
| Python (FastAPI, Django, Flask), TypeScript (Express, Fastify, Next.js), Go | official SDKs (TS7, TS7e) |
| Java (Spring), .NET (ASP.NET Core) | SDKs after M2; until then the recipes above plus generated API clients |
| Anything else (PHP, Ruby, Rust, Elixir, low-code) | recipes, OpenAPI-generated clients, contract SQL, test vectors, or the gateway |
| Databases other than Postgres | contract tables for MySQL/MariaDB, SQL Server and SQLite (TS7e); no RLS there, so the app filters by `tenant_id` or uses schema or database mode |

### 10.4 Proving it: the conformance kit

`matura conformance --app http://localhost:8000 --manifest matura.yaml` runs against any running app. It issues
tokens from a built-in test issuer for two tenants, sends signed events, and checks that the app:

- refuses requests without a token, with an expired token, or with a token for another audience;
- refuses an action whose permission is missing from `perms`;
- never returns tenant A's records to tenant B (it creates records as A through the app's own API, listed in the
  manifest's `conformance` section, then reads them as B);
- applies events idempotently and in version order, and catches up from the change feed;
- answers `tenant-not-ready` before its placement is ready (level 3).

## 11. Resource permissions (optional, TS11)

`perms` in the token says what a user may do in the tenant; it cannot say which records. For record-level sharing
an app declares an OpenFGA authorization model in its manifest and asks Matura. Mechanics and isolation are in the
[technical specification §16](02-technical-specification.md); the guide's §6.1 shows how to design for it.

```json
"authorization": { "model": "model\n  schema 1.1\ntype folder\n  relations\n    define tenant: [tenant]\n    define viewer: [user] or member from tenant\n..." }
```

The model may be the DSL (a string) or OpenFGA's JSON form; it defines the app's own types and may use Matura's:

| Type | Relations | Kept by Matura from |
|---|---|---|
| `user` | | |
| `group` | `member` | not yet written: groups arrive with SCIM (TS14) |
| `tenant` | `owner`, `admin` (includes owner), `billing`, `member` (includes admin and billing) | memberships and tenant roles |
| `workspace` | `tenant`, `member` and `admin` (from the tenant) | workspaces |
| `role` | `assignee` | app role grants: `role:<name>` tenant-wide, `role:<name>@<workspace id>` in one workspace |

The app's backend calls, with HTTP Basic (client id and secret), always naming one tenant that enabled the app:

| Call | Body | Answer |
|---|---|---|
| `POST /v1/apps/{app}/tenants/{tid}/relations` | `{"writes": [{"user", "relation", "object"}], "deletes": [...]}` (≤ 100) | `{"written", "deleted"}` |
| `POST /v1/apps/{app}/tenants/{tid}:check` | `{"user": "user:<sub>", "relation": "editor", "object": "document:d1"}` | `{"allowed": true}` |
| `POST /v1/apps/{app}/tenants/{tid}:batch-check` | `{"checks": [...]}` (≤ 50) | `{"results": [{"allowed": …, "error"?: …}]}` |
| `POST /v1/apps/{app}/tenants/{tid}:list-objects` | `{"user", "relation", "type": "document"}` | `{"objects": ["document:d1"]}` |

Users and objects are named as the app sees them (`user:<sub>`, `document:<id>`, `role:editor#assignee`,
`group:<id>#member`, `user:*`); Matura scopes every name to the tenant in the path, so the same ids in two tenants
never meet. Apps write tuples only on their own types. Each call accepts `"contextual_tuples"` (not stored) and
`"consistency": "higher"` (read a tuple written just before). An installation without OpenFGA answers `501`
(`permissions-not-configured`); an app without a model `409` (`no-authorization-model`); OpenFGA unreachable `503`
with `Retry-After`. SDK helpers: Python `MaturaAPI.check`, `batch_check`, `list_objects`, `write_relations`;
TypeScript `MaturaAPI.check`, `batchCheck`, `listObjects`, `writeRelations`; Go `Client.Check`, `BatchCheck`,
`ListObjects`, `WriteRelations`.
