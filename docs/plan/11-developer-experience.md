# 11 — Developer experience

## 1. SDKs

| SDK | What it does |
|---|---|
| **Python** (`matura`) | FastAPI/Starlette and Django middleware: verify tokens (JWKS cache, issuer/audience, clock skew), principal (`user`, `tenant`, `workspace`, `roles`, `mfa`), `require_role`, `require_permission`, `require_mfa`; grants cache with event invalidation; OpenFGA checks; SQLAlchemy/Alembic RLS helpers (`set_context`, migration ops); entitlements; usage events; audit events; webhook signature verification; OpenBao transit field encryption |
| **TypeScript** (`@matura/js`) | browser sign-in (OIDC code + PKCE, silent refresh, multi-tab), Node middleware (Express, Fastify, Next.js), same server helpers as Python |
| **React UI kit** (`@matura/react`) | `<MaturaProvider>`, `<SignInButton>`, `<UserMenu>`, `<TenantSwitcher>`, `<WorkspaceSwitcher>`, `<MembersTable>`, `<InviteDialog>`, `<RolePicker>`, `<SessionsList>`, `<SecuritySettings>`, `<AuditTable>`, hooks (`useUser`, `useRoles`, `usePermission`, `useEntitlement`) |
| **Go** (`matura-go`) | net/http and gRPC interceptors with the same features |

SDKs are generated from the OpenAPI spec for the API layer and hand-written for the middleware; all share a
conformance test suite.

## 2. CLI and infrastructure as code

- `matura` CLI: `login`, `install`, `tenants ...`, `apps apply`, `members invite`, `backup ...`, `dr ...`,
  `audit verify`, `support bundle`.
- OpenTofu/Terraform-compatible provider: tenants, workspaces, apps, roles, identity providers, policies, webhooks.
- Kubernetes CRDs via the operator for GitOps users.

## 3. Local development

- `docker compose up` gives the full stack with seeded tenants, users and Mailpit; `matura dev` creates a sandbox
  tenant and app client in one step.
- Test helpers: fake token issuer for unit tests (sign tokens with a test JWK), fixtures for two tenants, the
  cross-tenant test generator.
- Example apps: FastAPI + React, Next.js, Go.

## 4. Documentation

Docs site (MkDocs Material, MIT) with: quick-starts per stack, concepts, API reference (Redoc/Scalar from OpenAPI),
operator guide (install, upgrade, backup, DR, scaling, hardening), security whitepaper, compliance mappings,
runbooks, migration guides (from Auth0/Clerk/Cognito/Keycloak-only/Firebase Auth via import scripts with password
hash migration where the hash format allows).
