# Changelog

## Unreleased

### Added
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
- Realm: `matura-tenant` client scope, an `agentcanvas` client, Google and GitHub brokers (disabled until keys are set);
  Compose builds Keycloak with the extension.
- Build plan to 1.0 (docs/plan/21) and a guide for designing apps on Matura (docs/guide).
- Docker Compose stack with Postgres, Keycloak (realm `matura`), Mailpit and `maturad`; CI with Postgres-backed tests.
