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
- Docker Compose stack with Postgres, Keycloak (realm `matura`), Mailpit and `maturad`; CI with Postgres-backed tests.
