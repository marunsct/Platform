# 20 — End-to-end delivery plan

*2026-10-16 · proposed. Written after the owner asked for login, multi-tenancy, user management and roles to work
for DevFlow, AgentCanvas and any other app soon, with all three data-isolation modes, managed either by the app or
by Matura. Where this document and doc 13 disagree on order, this one wins once approved; doc 13 keeps the sprint
contents.*

Specifications: [functional](../spec/01-functional-specification.md) ·
[technical](../spec/02-technical-specification.md) · [app integration contract](../spec/03-app-integration-contract.md).

## 1. What changes against doc 13

Doc 13 reaches its first real app (AgentCanvas) in TS26, after 25 sprints. The owner's two products need sign-in,
tenants, members and roles first, so this plan pulls the identity and tenancy core forward and pushes the rest back:

| Change | Why |
|---|---|
| New milestone **M1 "first app signs in"** right after the control-plane skeleton, with DevFlow as the first app | DevFlow has no tenancy at all, so it proves the contract on a clean slate |
| New sprint **TS7b Data placement** (shared, schema, database × app-managed, platform-managed) | owner requirement (ADR 0006) |
| New sprint **TS7c App contract and sync** (contract tables, events, change feed) | owner requirement: one table structure for every app (ADR 0007) |
| AgentCanvas identity and tenancy move from TS26 to **TS9a**; its backup, privacy and readiness stay in TS26 | AgentCanvas already speaks OIDC and has organisations, so it is the second app |
| TS3 (design system) moves after M1 | sign-in can use a plain Keycloak theme until the consoles start |
| NATS, Temporal, OpenFGA and OpenBao are introduced when first needed, not in TS1 | keeps the first install to three containers (Postgres, Keycloak, `maturad`) |

## 2. Milestones

| Milestone | Sprints | What the owner can do at the end |
|---|---|---|
| **M0 Foundation** | TS1, TS2 | `docker compose up` runs Postgres, Keycloak and `maturad`; tenants, workspaces, users, memberships, apps, roles and placements exist in the API with row-level security and an outbox |
| **M1 First app signs in** | TS4-lite, TS5, TS6, TS7, TS7b, TS7c, TS7d | a user signs up, creates a company tenant, invites a colleague, assigns DevFlow roles; DevFlow reads tenant, user and roles from the token and its contract tables, and each tenant's data sits in the mode its plan requires |
| **M2 Second app and the portal** | TS9a, TS3, TS8 | AgentCanvas signs in through Matura with its four roles; tenant admins manage members, roles and workspaces in the customer portal instead of each app's own pages |
| **M3 Operator and security basics** | TS9, TS10, TS12 | operator console (tenants, plans, suspend, delete), security policies, MFA, session revocation |
| **M4 Enterprise identity** | TS11, TS13, TS14, TS15 | per-tenant SSO, SCIM, fine-grained permissions, agent identity |
| **M5 Production install** | TS16–TS23 | Helm, keys per tenant, entitlements, backups, observability, scale, DR, hardening |
| **M6 Readiness and 1.0** | TS24–TS27 | as doc 13 |

## 3. Sprints in M0 and M1

| Sprint | Work | Exit |
|---|---|---|
| **TS1 Repository and stack** | Go module, repository layout (doc 02 §7), Makefile, CI (lint, test, licence gate), Compose with Postgres 16, Keycloak 26 and `maturad`, realm-as-code with the `matura` realm, docs updated | `docker compose up` healthy; `make test` green |
| **TS2 Control-plane skeleton** | `maturad` REST API for tenants, workspaces, users, memberships, apps (manifest), roles, role grants, invitations (data only), database servers and placements; Postgres schema with RLS on tenant-owned tables; outbox; idempotency keys; problem+json errors; OpenAPI | API tests and a cross-tenant test pass; outbox rows written in the same transaction as each change |
| **TS4-lite Sign-in** | Keycloak realm: sign-up with email verification, password reset, Google and GitHub brokering, first-sign-in tenant choice (personal workspace or new company) | Playwright: sign up, verify, sign in, reset password |
| **TS5 Keycloak token mapper** | Java mapper adds `tid`, `wid`, `tenant`, `roles`, `ver` (doc 02 §4, contract §2); tenant selection via `tenant` request parameter or last used; event listener → `maturad` | a user in two tenants gets the right claims per tenant |
| **TS6 Onboarding and invitations** | invite by email (link default, temporary password option), accept, resend, revoke, expire; Mailpit in Compose | an invited user joins with the right roles |
| **TS7 Python SDK v0** | FastAPI middleware: token check with JWKS cache, `Principal`, `require_role`, `require_permission`, tenant context for RLS, fake issuer for tests | example app works with two tenants; app keeps serving with `maturad` stopped |
| **TS7b Data placement** | database-server registry, placement API, provisioning jobs for `shared`, `schema` and `database` with `manager: platform`; registration for `manager: app`; SDK connection router; migration hand-off; delete with confirmation | the example app serves three tenants in three modes, two platform-managed and one app-managed, and the cross-tenant suite passes in each mode |
| **TS7c App contract and sync** | contract tables migration (Alembic op and plain SQL), just-in-time upsert from tokens, signed webhooks from the outbox, change feed with cursors, versioned idempotent apply | killing the webhook receiver for an hour loses no change after the feed catches up |
| **TS7d DevFlow on Matura** | DevFlow replaces its `users` table and HS256 tokens with the SDK; adds `tenant_id` and RLS to its run and audit tables; roles `admin`, `operator`, `viewer` registered from its manifest | DevFlow runs for two tenants with no data crossing; its old local sign-in still works behind a flag during migration |

## 4. Ways of working

- One sprint per pull request against this branch's base; each ends with tests green, docs updated, a changelog
  entry and HANDOVER.md updated (HANDOVER §5).
- Each app integration (DevFlow, AgentCanvas) is a pull request in that app's repository, linked from the Matura
  sprint.
- ADRs 0001–0007 move to `accepted` when the owner approves this plan.

## 5. Decisions taken by default (change any of them by saying so)

| Question | Default |
|---|---|
| Build or wrap the identity server | wrap Keycloak (ADR 0001) |
| Control-plane language | Go (ADR 0003) |
| What a tenant is | a customer company, or a shared tenant for individuals; a user can belong to many tenants (doc 04) |
| Who owns roles | Matura stores each app's role catalogue from its manifest and the grants; the app enforces them |
| First sign-in methods | email and password, Google, GitHub; MFA and passkeys in M3; SAML and OIDC SSO in M4 |
| Billing | plans and limits only (TS18); payments later through adapters |
| Hosting | self-hosted, Docker Compose first, Helm in M5 |
| Data isolation | all three modes, app-managed or platform-managed (ADR 0006); new tenants default to `shared` |
