# Designing an app for Matura

*Version 1 · 2026-10-17. For developers building a new app on Matura, or moving an existing one (DevFlow,
AgentCanvas or any other) onto it. It explains the design rules behind the
[app integration contract](../spec/03-app-integration-contract.md); the contract is the reference, this guide is the
"how and why".*

## 1. The one-paragraph version

Matura owns **who** someone is, **which tenant** they act for, and **what they may do**. Your app owns **what it
does** and **its data**. So the app never stores passwords, never has its own sign-up, members or roles pages, and
never decides roles: it reads the caller from a signed token, checks a permission, and keeps a read-only copy of
tenants, users and memberships in the shared `matura_*` tables so its own rows can point at them. Every row your
app owns carries `tenant_id`, and the database (row-level security, a schema or a whole database per tenant) keeps
tenants apart even when your code has a bug.

## 2. What lives where

| Concern | Matura | Your app |
|---|---|---|
| Sign-up, sign-in, password reset, MFA, SSO, social login | ✓ (Keycloak) | redirects to it (OIDC) |
| Tenants, workspaces, members, invitations | ✓ | reads them (`matura_*` tables) |
| Role definitions and who holds which role | ✓ (portal and API) | declares the **permissions** its code checks |
| Permission check on each request | | ✓ reads `perms` from the token |
| Business data (runs, documents, canvases …) | | ✓ with `tenant_id` on every row |
| Where each tenant's data is stored | decides mode per plan; can create schemas and databases | runs its migrations there |
| Audit of identity, membership and role changes | ✓ | records its own business actions (to Matura's audit from M3) |
| App settings per user | | ✓ in its own table keyed by `user_id` |

If you are about to build a screen for inviting people, changing someone's role or creating an organisation: stop,
link to the Matura portal instead (§9).

## 3. Shape of a Matura-ready app

```
 browser ──OIDC──► Matura sign-in (Keycloak)
    │  access token (tid, wid, roles, perms, ver)
    ▼
 ┌──────────────────────── your app ──────────────────────────┐
 │ 1. verify token (JWKS, issuer, audience = your client id)  │
 │ 2. Principal { user, tenant, workspace, perms }            │
 │ 3. require_permission("doc.edit")                          │
 │ 4. tenant session: route to tenant's placement, set        │
 │    matura.tenant_id for the transaction                    │
 │ 5. business logic on your tables (tenant_id on every row)  │
 │                                                            │
 │ POST /matura/events  ◄── signed webhooks (changes)         │
 │ feed reader at start-up and hourly ◄── change feed         │
 │            both write matura_* tables by version           │
 └────────────────────────────────────────────────────────────┘
```

Two rules make it fast and robust (doc 17): **the request path never calls Matura** (the token and the local tables
are enough), and **the app keeps working when Matura is down** (tokens stay valid until they expire; events queue
and the feed catches up).

## 4. Pick your integration level

You can adopt Matura in steps; each level works in any language (ADR 0009).

| Level | You get | You build |
|---|---|---|
| 0 Gateway | sign-in and tenant headers with no code change | trust only the gateway; read `X-Matura-*` headers |
| 1 Sign-in | users, tenants, roles and permissions on every request | an OIDC login, a JWT check, `perms` checks |
| 2 Directory | names, emails and members of people who are not signed in; removals | contract tables, one webhook endpoint, a feed reader |
| 3 Data placement | tenants on shared, schema or database storage, created by Matura or by you | ask for the placement, route connections, migrate on `placement.provisioned` |

Most apps want level 2: any screen that lists people ("assigned to", "created by", a members picker) needs it.

## 5. Identity: design rules

1. **Use Matura's user id everywhere.** `sub` in the token is `matura_user.id`. Never key anything on email; emails
   change and get reused.
2. **No local passwords, no local sign-up.** Sign-in is an OIDC redirect with PKCE (browser) or the client-credentials
   grant (services). Remove old login code once migrated; keep it behind a flag for one release at most.
3. **Short-lived tokens, no sessions of your own that outlive them.** Access tokens live 5 minutes; refresh through
   the OIDC client library. If you keep a server-side session, store the refresh token, not user data.
4. **Machine callers are users too.** Background workers and other services use their own client credentials; the
   token's `azp` names them and `perms` limits them. Never reuse a human's token in a job.
5. **Tenant switching is a new token.** To change tenant, redirect to sign-in with `matura_tenant=<slug>`; never
   accept a tenant id from a request header or body as the source of truth.

## 6. Authorisation: design rules

1. **Declare permissions, not roles.** Your manifest lists the actions your code checks, named `resource.action`:

   ```yaml
   spec:
     permissions:
       - { name: doc.read,    description: Open documents }
       - { name: doc.edit,    description: Edit documents }
       - { name: doc.share,   description: Share outside the workspace }
       - { name: billing.view, description: See invoices }
     roles:                     # starter roles only; tenant admins and operators edit them in Matura
       - { name: editor, permissions: [doc.read, doc.edit] }
       - { name: viewer, permissions: [doc.read] }
     defaultRole: viewer
   ```

2. **Check `perms` in code, never role names.** Roles are renamed and edited in Matura; permissions are stable
   because your code defines them. `"*"` means everything.

   ```python
   @app.post("/docs/{id}/share")
   def share(id: UUID, p: Principal = Depends(require_permission("doc.share"))): ...
   ```

3. **Check on the server, hide in the UI.** The UI may hide a button when `perms` lacks it; the API must still refuse.
4. **Keep permissions coarse enough to understand.** 10–40 per app is typical. Above 40 a token carries `perms_ref`
   and the SDK reads the role table instead.
5. **Record-level rules stay in your code until M4.** "Only the author may delete a draft" is a check on your own
   data (`created_by = p.user_id`). Fine-grained sharing per record moves to OpenFGA in TS11 through the same SDK.
6. **Never widen a permission by renaming it.** Add a new permission, ship code that checks it, then remove the old
   one; the manifest refuses removals that a role still uses.

## 7. Data: design rules

### 7.1 Every tenant-owned table

```sql
CREATE TABLE docs (
    tenant_id    uuid NOT NULL REFERENCES matura_tenant(id),
    workspace_id uuid NOT NULL,
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    title        text NOT NULL,
    created_by   uuid NOT NULL REFERENCES matura_user(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES matura_workspace(tenant_id, id)
);
CREATE INDEX docs_ws ON docs (tenant_id, workspace_id, created_at DESC);

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON docs
  USING (tenant_id = current_setting('matura.tenant_id', true)::uuid);

CREATE TABLE doc_comments (
    tenant_id  uuid NOT NULL,
    doc_id     uuid NOT NULL,
    id         uuid NOT NULL DEFAULT gen_random_uuid(),
    body       text NOT NULL,
    author_id  uuid NOT NULL REFERENCES matura_user(id),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, doc_id) REFERENCES docs(tenant_id, id)  -- a comment cannot point into another tenant
);
```

Rules behind it:

1. `tenant_id` on every tenant-owned row, in **every** mode, so a tenant can later move between modes.
2. Composite keys `(tenant_id, id)` and composite foreign keys, so children cannot cross tenants.
3. People columns reference `matura_user(id)`.
4. Indexes lead with `tenant_id`.
5. Row-level security in shared mode, set per transaction with `set_config('matura.tenant_id', …, true)`.
   `current_setting(…, true)` returns NULL when nothing is set, so a forgotten tenant returns **no rows**, not all.
6. The app connects as a role **without** `BYPASSRLS` that owns no tables; migrations run as the owner role.
7. Tables that are not tenant-owned (feature catalogues, country lists) have no `tenant_id` and no policy; keep them
   few and obviously global.

### 7.2 Don't

- Don't add columns to `matura_*` tables. Put app-specific user data in your own table:
  `docs_user_settings(tenant_id, user_id, theme, …)`.
- Don't write to `matura_*` tables yourself; only the SDK's apply (or your level-2 receiver) does, by version.
- Don't join across tenants in application queries. Cross-tenant reports belong to operator tooling with an
  explicit operator scope.
- Don't cache anything per user without the tenant in the key: `cache_key = f"{tenant_id}:{user_id}:…"`.
- Don't put tenant data in global object-storage paths: use `s3://bucket/<tenant_id>/…` and check the prefix.

### 7.3 Storage modes

Write the app once; the mode changes only where the connection goes.

| Mode | Use for | Your app does |
|---|---|---|
| `shared` | most tenants, free and standard plans | one connection pool; `set_config` each transaction |
| `schema` | larger tenants wanting separation without many databases | `SET LOCAL search_path` to the tenant's schema (SDK does it) |
| `database` | enterprise, residency, customer-managed keys | one small pool per tenant database (SDK keeps an LRU) |

Who creates the storage is the **manager**: `platform` (Matura creates the database or schema and a role for it,
and hands your app short-lived credentials) or `app` (you create it and register it with Matura). Prefer `platform`
unless you already run per-tenant databases.

### 7.4 Migrations

- Run migrations per placement: `matura migrate --all-tenants` or on each `placement.provisioned` event.
- Use **expand and contract**: tenants upgrade one after another, so old and new code run against both shapes for a
  while. Add a column nullable, backfill, then make it required in a later release.
- Report readiness: call `POST /v1/apps/{app}/placements/{tid}:ready` after migrating a new placement. Until then
  requests for that tenant get `503 tenant-not-ready`.

## 8. Keeping the directory in sync (level 2)

1. Create the contract tables with the shipped SQL (`matura.contract.v1`) before your own migrations.
2. Expose one endpoint, for example `POST /matura/events`. Verify `Matura-Signature`, refuse anything older than
   5 minutes, skip ids already in `matura_inbox`, apply by version, answer 2xx quickly. Do slow work later.
3. Read the change feed at start-up and every hour from the stored cursor. If the cursor is too old (`410`), take a
   snapshot.
4. React to events that matter to your logic:

| Event | Typical reaction |
|---|---|
| `membership.removed`, `user.deactivated` | unassign open tasks, stop scheduled jobs owned by the user |
| `user.deleted` | nothing to do: the row stays with name and email cleared, your foreign keys still work |
| `tenant.suspended` | stop background work for the tenant; requests are already refused at sign-in |
| `tenant.deleting` | delete the tenant's data and objects, then call `POST …/placements/{tid}:deleted` |
| `placement.provisioned` | run migrations on the new storage, then `:ready` |
| `app.role.updated` | nothing: new tokens carry the new `perms`; refresh `matura_app_role` for `perms_ref` |

Apply is idempotent and order-independent because of the version rule, so retries and duplicates are safe.

## 9. User interface

1. **Sign-in button, not a sign-in form.** Redirect to Matura; it themes per tenant.
2. **Tenant switcher.** Show the tenants from `GET /v1/me/tenants`; switching re-authenticates with
   `matura_tenant=<slug>`.
3. **People pickers read `matura_user` joined with `matura_membership`** for the current tenant; never call Matura
   on each keystroke.
4. **Link to the portal** for members, invitations, roles, SSO and security settings
   (`https://<matura>/portal/<tenant>/members`), or embed the Matura widgets when they ship (TS7, `@matura/react`).
5. **Explain refusals.** A 403 says which permission is missing, so a tenant admin knows which role to grant.
6. **Show "deleted user"** when `matura_user.status = 'deleted'`.

## 10. Background jobs, APIs and agents

- Jobs carry `tenant_id` in their payload and open a tenant session before touching data; a job without a tenant is
  an operator job and must say so.
- Public APIs of your app accept Matura tokens (users or service accounts); don't issue your own API keys. Service
  accounts and API keys come from the portal (TS8).
- AI agents acting for a user get their own identity and scoped, revocable tokens (TS15); design tool calls so the
  agent's token, not the user's, reaches your API.

## 11. Testing your app

| Test | How |
|---|---|
| Unit tests with tokens | the SDK's fake issuer mints tokens for any tenant, roles and perms |
| Cross-tenant | create records as tenant A, read and write them as tenant B through every route: expect 404 |
| RLS fails closed | open a transaction without `matura.tenant_id`: every tenant table returns no rows |
| Sync | feed shuffled and duplicated events: the contract tables end in the same state |
| Conformance | `matura conformance --app <url> --manifest matura.yaml` before each release |
| Modes | run the cross-tenant suite once per storage mode your app supports |

## 12. Checklist before you ship

- [ ] Manifest lists every permission the code checks; starter roles and a default role are set.
- [ ] Every route checks a permission on the server, or is explicitly public.
- [ ] Token verification checks signature, issuer, audience and expiry; JWKS cached.
- [ ] No local passwords, sign-up, members or roles pages remain (or they are behind a flag for one release).
- [ ] Every tenant-owned table has `tenant_id`, composite keys, a leading index and, in shared mode, forced RLS.
- [ ] App connects as a non-owner role without `BYPASSRLS`.
- [ ] Contract tables are created first; webhook endpoint verifies signatures and records event ids.
- [ ] Feed reader runs at start-up and hourly; cursor stored.
- [ ] Caches, object-storage paths, queues and logs include the tenant.
- [ ] Tenant deletion removes the app's data and confirms with `:deleted`.
- [ ] Cross-tenant suite and conformance kit pass.

## 13. Moving an existing app

1. Write the manifest (permissions from the checks your code already does; starter roles matching today's roles).
2. Add the contract tables and the webhook endpoint; import existing users into Matura (the import keeps their ids
   or maps old ids to Matura ids in a mapping table).
3. Add `tenant_id` to your tables; for an app without tenants, put all existing data into one tenant first.
4. Switch sign-in to Matura behind a flag; keep the old login for one release.
5. Replace role checks with permission checks; remove members and roles screens; link to the portal.
6. Turn on RLS and run the cross-tenant suite and the conformance kit.

DevFlow (TS7d) and AgentCanvas (TS9a) follow these steps; their pull requests are the worked examples.
