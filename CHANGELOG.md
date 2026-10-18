# Changelog

## Unreleased

### Added
- Portal pages for Agents, Directory sync (SCIM tokens and group mappings) and the Audit log. Source only: run
  `npm ci && npm run typecheck && npm test && npm run build` in web/portal and commit `internal/portal/dist`.
- Agents and service accounts as tenant principals (TS15): agent tokens through Keycloak carry `kind` and `act`
  (who the agent acts for); SDK helpers for principal kind and protected resources; migration 0015
  (docs/guide/agents.md, spec 02 §20).
- SCIM 2.0 per tenant (TS14): users and groups provisioned from Okta or Entra ID, groups feeding OpenFGA; migration
  0014 (docs/guide/scim.md, spec 02 §19).
- Fine-grained permissions on OpenFGA (TS11): a syncer writes tuples from memberships and grants; check and list
  endpoints answer 501 until `MATURA_OPENFGA_URL` is set; Compose runs OpenFGA (migration 0013, spec 02 §18).
- MFA and sessions (TS12): tenants can require a second factor (Keycloak authenticator `matura-mfa-policy`); users
  list and end their sessions; owners list members' sessions and reset their MFA (spec 02 §16).
- Per-tenant SSO (TS13): tenants connect an OIDC or SAML identity provider, verify their email domains, and sign-ins
  through it join the tenant just in time; other domains are refused (migration 0011, docs/guide/sso.md, §17).
- Readiness and trust (TS24, TS25): `matura check` scores an installation's settings, collects evidence, and an
  optional public trust page; policy templates in docs/templates (docs/guide/readiness.md, §15).
- Data rights and retention (TS17): tenant export, user access and erasure requests (Keycloak accounts of erased
  users are deleted), audit retention (migration 0012, §14).
- Operator console backend (TS10): tenant lifecycle (suspend, delete with a grace period, purge), entitlements and
  time-boxed support access (migration 0009, §5.3).
- Audit log (TS9): every change is written with a hash chain in the same transaction, streamed to external sinks, and
  readable per tenant; tenant security policies (migration 0008, §13).
- Customer portal (TS3, TS8), served by maturad at `/portal/`: members, invitations, apps, workspaces, roles and the
  user's own account, on a small design system with PKCE sign-in (docs/guide/portal.md).
- Go SDK (`sdk/go`, its own module); placement changes are versioned on their own in the contract tables, which
  closes the late-replay gap in the Python and TypeScript SDKs.
- Helm chart (`deploy/helm/matura`: maturad, Keycloak, ingress, network policy, ServiceMonitor), backup and restore
  tooling (`scripts/backup.sh`) and Prometheus metrics on a separate listener (`MATURA_METRICS_ADDR`)
  (docs/guide/kubernetes.md, docs/guide/backup.md).
- The realm's SMTP server comes from `MATURA_KEYCLOAK_SMTP_HOST`, `_PORT` and `_FROM` (the chart sets them from
  `smtp`), so Keycloak's verification and reset emails reach a real mail server.

### Fixed
- maturad's connection pool now has room beside the background leaders. Each leader holds a connection for as long
  as it leads, and pgx's default of max(4, CPUs) left none for requests on a small machine: sign-in hung on the MFA
  policy call. The pool gets nine more connections unless the URL sets `pool_max_conns`.
- Manifests may carry a `conformance` section (kept, not used by maturad). AgentCanvas passes all 19
  `matura-conformance` checks; the run found and fixed a role-mapping gap in AgentCanvas#49.
- TypeScript SDK `@matura/sdk` (sdk/typescript, no runtime dependencies): token verification, `Principal`, webhook
  signatures, contract tables with the version rule, change feed and placement client, framework-agnostic HTTP
  helpers and a fake issuer; runs the shared test vectors.
- `matura-conformance` (`cmd/matura-conformance`, `internal/conformance`): a black-box checker for any app. It runs a
  test issuer, seeds two tenants with signed events, and checks token refusals, permissions, tenant isolation through
  the app's own API (manifest `conformance` section) and webhook signature handling (docs/guide/conformance.md).
- `scripts/e2e_invite_signup.mjs`: browser test of sign-up, invitation and the resulting AgentCanvas token claims
  against running Keycloak, maturad and Mailpit.
- OpenAPI 3.1 document for every maturad route (`api/openapi.yaml`), with a test that fails when the router and the
  document disagree.
- Any-language kit, first part (TS7e): contract SQL for PostgreSQL (plus shared-mode RLS), MySQL/MariaDB, SQL Server
  and SQLite with version-rule upserts per database (`docs/contract/sql`); token and apply vectors added to
  `docs/contract/test-vectors.json` (`scripts/gen_contract_vectors.py`), run by the Python SDK.
- Invitations and email (TS6): admins invite by email with a tenant role and app roles (`/v1/tenants/{tid}/invitations`,
  resend, revoke); links carry a single-use token stored only as a hash and expire after 7 days; the invitee accepts
  on maturad's page (`/invitations/accept`, Keycloak sign-in or sign-up with PKCE) or through
  `POST /v1/invitations:accept`. New members get each enabled app's default role unless the invitation names one
  (RL-4), also when added directly. Email outbox written with the change and an SMTP mailer with retries (migration
  0007; `MATURA_SMTP_*`, `MATURA_PUBLIC_URL`); Compose sends through Mailpit.
- Data placement (TS7b): a provisioner creates platform-managed storage on registered database servers (shared:
  `<app>_shared` with owner and runtime roles; schema: `t_<tenant>` in `<app>_bridge`, owned by the tenant's role;
  database: `<app>_t_<tenant>`, CONNECT revoked from PUBLIC), retries failed steps, and drops a deleted tenant's
  schema or database once the app confirms its data is gone. App endpoints: `GET`/`PUT /v1/apps/{app}/placements/{tid}`,
  `POST …/{tid}:ready`, `…/{tid}:deleted`, `…/{tid}/credentials` (runtime or migrate); tenants read
  `GET /v1/tenants/{tid}/placements`. Deleting a tenant moves its placements to `retiring`. Python SDK:
  `MaturaAPI.placement`, `register_placement`, `credentials`, `placement_ready`, `placement_deleted`.
- End-to-end delivery plan (docs/plan/20), functional and technical specifications and the app integration contract
  (docs/spec), ADR 0006 (data placement modes) and ADR 0007 (contract tables).
- `maturad` control plane: tenants, workspaces, members, apps from manifests, app roles and grants, tenant apps with
  data placement selection, all behind Postgres row-level security that fails closed, with a versioned outbox.
- Roles managed in Matura (ADR 0008): apps declare a permission catalogue; operators create, rename, edit and delete
  roles through `/admin/v1/apps/{app}/roles`; re-applied manifests never overwrite them.
- Any-language integration design (ADR 0009) and contract §10: integration levels, recipes, test vectors and the
  conformance kit (planned in TS7e).
- Operator endpoints for plans and database servers, including a connection test (`POST /admin/v1/db-servers/{id}/test`).
- Stored secrets are envelope-encrypted under `MATURA_KEK` (required outside development); database server passwords
  are never returned, only a fingerprint.
- `Idempotency-Key` on POST requests: retries replay the first response for 24 hours; reusing a key for a different
  request answers 422, and a retry racing the first attempt answers 409.
- `GET /v1/me/tenants` and operator user management (`/admin/v1/users`: search, deactivate, delete with the row kept
  anonymised).
- App backends authenticate with their client id and a secret (`/admin/v1/apps/{app}/secrets`) and read their change
  feed (`GET /v1/apps/{app}/changes`) and snapshots (`GET /v1/apps/{app}/snapshot`), filtered to tenants that enabled
  the app.
- Signed webhooks (`/admin/v1/apps/{app}/webhooks`): CloudEvents delivered in order per endpoint with
  `Matura-Signature`, retried with backoff for 24 hours, plus a test delivery.
- Token claims for apps: `POST /internal/v1/token-context` (tenant, workspace, tenant role, app roles, permissions
  or `perms_ref`, versions, placement mode; refusals for non-members, disabled apps and inactive users) and the
  Keycloak extension `matura-token-mapper` that puts them in access tokens (keycloak/extensions, Java 21).
- Realm: an `agentcanvas` client carrying the token mapper (on the client, so the import keeps Keycloak's built-in
  scopes such as `basic`, which carries `sub`), Google and GitHub brokers (disabled until keys are set);
  Compose builds Keycloak with the extension.
- Python SDK `matura` (sdk/python): token verification and `Principal`, `require_permission` for FastAPI, the
  `matura_*` contract tables for PostgreSQL (with shared-mode RLS) and SQLite, `apply` with the version rule and
  hooks, signed webhook receiver, change-feed sync with snapshot bootstrap, and a fake issuer for tests.
- Shared webhook signature test vectors (docs/contract/test-vectors.json), checked by the Go and Python tests;
  `scripts/e2e_python_sdk.py` checks the SDK against a running maturad.
- Build plan to 1.0 (docs/plan/21) and a guide for designing apps on Matura (docs/guide).
- Docker Compose stack with Postgres, Keycloak (realm `matura`), Mailpit and `maturad`; CI with Postgres-backed tests.
