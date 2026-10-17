# 21 — Build plan to finish the product

*2026-10-17 · proposed. Written after the owner asked to "start planning and start the development, finish the
product", and for a guide on how apps should be designed for Matura ([docs/guide](../guide/README.md)). Doc 20 sets
the milestone order and doc 13 the sprint contents; this document turns them into a build sequence and says how
"finished" is measured.*

## 1. What "finished" means

Matura is finished when version 1.0 ships: TS1–TS27 of doc 13 in the order of doc 20, ending with a signed release,
a third-party penetration test and AgentCanvas running on it. That is six milestones. Each one is a usable product
on its own, so the owner's apps adopt Matura at M1 and keep gaining features without changing their integration:
the token, the contract tables, the events and the change feed stay the same from M1 to 1.0 (contract v1).

| Milestone | Usable result | State on 2026-10-17 |
|---|---|---|
| M0 Foundation | API, schema with row-level security, outbox | built (PR #1, #2, #3) |
| M1 First app signs in | sign-up, tenants, invitations, roles, tokens with `perms`, contract sync, three data modes, SDKs, conformance kit, **AgentCanvas** on Matura | **building now** (§3) |
| M2 Second app and portal | DevFlow on Matura; tenant admins use the customer portal | next |
| M3 Operator and security basics | operator console, MFA, sessions, security policies, audit log | |
| M4 Enterprise identity | per-tenant SSO, SCIM, fine-grained permissions, agent identity | |
| M5 Production install | Helm, per-tenant keys, entitlements, backups, observability, scale, DR, hardening | |
| M6 Readiness and 1.0 | control packs, readiness score, evidence, trust page, migration kits, 1.0 | |

## 2. How the work is run

- **One slice at a time, always shippable.** Each slice is a commit (or a pull request) with code, tests, the
  OpenAPI document, the changelog and HANDOVER.md updated. Nothing is left half-wired on `main`.
- **Tests that prove the promise.** Every slice adds to the cross-tenant suite; provisioning is tested against a real
  Postgres; SDKs are tested with a fake issuer and shuffled, duplicated events; the conformance kit runs against the
  sample apps in each language.
- **Verified locally until CI has runners.** GitHub Actions on the owner's account starts no jobs (see PR #3), so
  each push is checked with `gofmt`, `go vet` and `go test -race` against Postgres 16 first.
- **App repositories get their own pull requests.** AgentCanvas (TS9a, first, at the owner's request on 2026-10-17)
  and DevFlow (TS7d, in M2) adopt Matura in their own repositories, linked from the Matura slice.

## 3. M1 build sequence

Ordered so that each step is testable without the next one.

| # | Slice | Sprint | Builds | Done when |
|---|---|---|---|---|
| 1 | Finish the control plane | TS2 | `/v1/me`, `/v1/me/tenants`, operator user endpoints, `api/openapi.yaml` covering every route | OpenAPI lints and every route in the router appears in it (test) |
| 2 | App credentials and change feed | TS7c | app API clients (client id + secret, hashed), `GET /v1/apps/{app}/changes` and `/snapshot`, per-app event filtering | an app reads only tenants that enabled it, in commit order, from a cursor |
| 3 | Webhooks | TS7c | webhook endpoints per app, outbox relay with one leader (`pg_try_advisory_lock`), signed delivery (`Matura-Signature`), backoff for 24 h, test endpoint | a receiver that is down for a while gets every event once it is back; signatures verify |
| 4 | Data placement | TS7b | placement API (`GET`, app-managed `PUT`, `:ready`, `:deleted`, credentials), provisioner for `shared`, `schema` and `database` on registered servers, deletion | the provisioner creates all three on the test Postgres and one tenant's role cannot read another's schema or database |
| 5 | Invitations and email | TS6 | invitations (hashed single-use tokens, expiry, resend, revoke, accept), email outbox and SMTP sender (Mailpit in Compose) | an invited user accepts and gets the right tenant role and app roles |
| 6 | Token context for Keycloak | TS5 | `/internal/v1/token-context` (tid, tenant, wid, troles, roles, perms or perms_ref, ver, pmode) and the Java protocol mapper that calls it | a user in two tenants gets the right claims for each; a tenant without the app is refused |
| 7 | Sign-in realm | TS4-lite | realm-as-code: sign-up, verify email, reset password, Google and GitHub brokers (disabled until keys are set), `matura-api` audience, app client template | realm imports; documented first-run |
| 8 | Python SDK | TS7 | token verification with JWKS cache, `Principal`, `require_permission`, contract tables migration, `apply` with the version rule, webhook receiver, feed reader, tenant session routing for three modes | example FastAPI app serves two tenants; keeps serving with `maturad` stopped |
| 9 | Any-language kit | TS7e | contract SQL for Postgres, MySQL, SQL Server, SQLite; token and event test vectors; TypeScript SDK; `matura conformance` CLI | the sample apps pass the kit; a deliberately leaky app fails it |
| 10 | AgentCanvas on Matura (draft [AgentCanvas#49](https://github.com/marunsct/AgentCanvas/pull/49)) | TS9a | AgentCanvas pull request (FastAPI + React): Python SDK, contract tables, its `organization`/`app_user`/`membership` mapped onto `matura_*`, `org_id` → `tenant_id` with RLS, manifest with its four roles, sign-in through Matura behind a flag | AgentCanvas runs for two tenants with no data crossing; its own sign-in still works behind the flag |

## 4. After M1

| Milestone | Sprints | First slice |
|---|---|---|
| M2 | TS7d DevFlow on Matura, TS3 design system and app shell, TS8 customer portal I | DevFlow pull request using the Python SDK; then the portal shell on the design system |
| M3 | TS9 portal II, TS10 operator console, TS12 MFA and sessions | audit log from the outbox with hash chains (the outbox already records every change) |
| M4 | TS11 OpenFGA, TS13 SSO, TS14 SCIM, TS15 agent identity | per-tenant SSO wizard on Keycloak brokering |
| M5 | TS16–TS23 | Helm chart with the same three containers as Compose |
| M6 | TS24–TS27 | `matura check` readiness score over settings that already exist |

## 5. Risks to finishing

| Risk | What we do |
|---|---|
| CI has no runners | verify locally on every push; the owner checks Settings → Billing and plans for Actions |
| Keycloak cannot run in the build container (no Docker daemon) | the mapper is unit-tested with Keycloak's own model mocks and its SPI jars from Maven Central; end-to-end sign-in tests run in Compose on the owner's machine |
| Scope of 1.0 is large | each milestone is releasable; apps integrate once at M1 and keep the same contract to 1.0 |
| App repositories drift | AgentCanvas and DevFlow pull requests pin the contract version (`matura.contract.v1`) and run the conformance kit |
