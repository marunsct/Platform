# 0009 — Integration is defined in open standards, so any language or framework works

Status: proposed · 2026-10-16

## Context
DevFlow and AgentCanvas are Python, but Matura must serve apps written in any language or framework (Node, Java,
.NET, Go, PHP, Ruby, Rust, low-code tools). An SDK-only design would leave every other stack behind.

## Decision
The contract between Matura and an app is defined only in things every stack already has:

| Need | Standard | What an app without an SDK uses |
|---|---|---|
| Sign-in | OpenID Connect, authorization code + PKCE | any certified OIDC client library |
| Who is calling, tenant, roles, permissions | JWT access token, keys from JWKS | any JWT library |
| User and tenant data in the app | plain SQL files for the contract tables | the app's own migration tool |
| Changes | CloudEvents 1.0 over HTTPS webhooks, HMAC-SHA256 | about 20 lines of code, checked against published test vectors |
| Catch-up and bootstrap | REST change feed, OpenAPI 3.1 | any HTTP client or a client generated from the OpenAPI file |
| Tenant isolation in Postgres | `set_config('matura.tenant_id', …, true)` per transaction | one SQL statement |
| Apps that cannot change their code | an identity-aware proxy | headers set by `matura-gateway` |

Integration comes in levels, each usable on its own: **0 Gateway** (no code change), **1 Sign-in** (verify the
token, read `tid`, `roles`, `perms`), **2 Directory** (contract tables kept current by events and the feed),
**3 Data placement** (per-tenant storage routed by placement). Official SDKs (Python, TypeScript, Go first; Java and
.NET next) are conveniences over the same contract, never required. A **conformance kit** (`matura conformance`)
checks any running app from the outside: it signs test tokens with a test issuer, sends signed events, and confirms
the app refuses other tenants' data and missing permissions.

## Alternatives
- SDK required: fastest for the languages we ship, unusable for the rest.
- A sidecar for every app: works everywhere, but adds a process to every deployment; kept as the optional gateway.

## Consequences
+ Any stack can integrate on day one with ordinary libraries; SDKs make it shorter, not possible.
+ The conformance kit gives every app, whatever its language, the same proof of isolation.
− The contract must stay stable and versioned (`matura.contract.v1`), with test vectors for signatures and claims.
− Row-level security in shared mode is Postgres-only; on other databases the app filters by `tenant_id` itself or uses
  schema or database mode.
