# 13 — Roadmap

Sprints are numbered `TS1…` (Tenantry sprint) to stay apart from AgentCanvas sprints. Each sprint ends with tests
green, docs updated, a changelog entry and a tagged pre-release. Exit criteria are checked by automated tests where
possible.

## Phase 0 — Foundation

| Sprint | Work | Exit |
|---|---|---|
| **TS1 Repository and stack** | repo layout, CI (lint, test, licence check, SBOM, cosign), ADRs 0001–0005 accepted, licence audit of every component (`deps/licences.yaml`), Compose stack (Keycloak 26, Postgres, Valkey, NATS, OpenFGA, OpenBao dev, SeaweedFS, Mailpit, Temporal), realm-as-code, docs site skeleton | `docker compose up` brings every component healthy; CI green with licence gate |
| **TS2 Control plane skeleton** | `tenantryd` with tenants, workspaces, users, memberships, apps, grants; Postgres schema with RLS on its own tables; OpenAPI spec and generated clients; outbox → NATS; audit table with hash chain; Temporal worker skeleton | API tests for CRUD; cross-tenant tests on the control plane pass; `tenantry audit verify` passes |

## Phase 1 — Identity

| Sprint | Work | Exit |
|---|---|---|
| **TS3 Sign-in and sign-up** | Keycloakify theme (light/dark, i18n), sign-up with email verification, Google and GitHub brokering, first-sign-in choice (shared tenant + personal workspace, or new company tenant), forgot/reset password, password policy and breached-password mirror, lockout | Playwright: sign up, verify, sign in, reset password, social login against a mock OIDC provider |
| **TS4 Keycloak extensions** | tenant token mapper (tid, wid, roles), event listener → NATS → audit, temporary-password required action with expiry, verify-alternate-address action, tenant-scoped admin endpoints | extension unit tests (Keycloak testsuite); tokens carry correct claims for a user in two tenants |
| **TS5 Onboarding and invitations** | invite by email with link or temporary password, deliver-to-other-address, bulk CSV, resend/revoke/expire, email outbox with templates, SMTP settings, tenant creation with owner | Playwright: admin onboards a user by temporary password, forced change, correct roles; expired temp password refused |
| **TS6 SDKs v0** | Python and TypeScript SDKs (verify, principal, roles, grants cache, RLS helper), React kit basics (provider, user menu, switchers), example FastAPI + React app | example app works end to end with two tenants; SDK conformance suite green |

## Phase 2 — Tenancy and consoles

| Sprint | Work | Exit |
|---|---|---|
| **TS7 Tenant admin console I** | members, invitations, groups, workspaces, apps, roles (incl. custom roles), API keys and service accounts | tenant owner completes every members/roles task without the API |
| **TS8 Tenant admin console II** | sessions, security policies (MFA required, methods, sessions, IP allow-list), audit view and export, webhooks, branding, account portal | policy changes take effect within a minute; audit export matches the chain |
| **TS9 Platform admin console** | tenants lifecycle (create, suspend, delete with grace and crypto-shred), users across tenants, shared-tenant controls, plans and entitlements, support access with consented impersonation, security center v1 | impersonation requires approval, shows a banner, expires, appears in both audit logs |
| **TS10 Fine-grained permissions** | OpenFGA integration, app authorisation models from manifests, check/list APIs, "who has access" views, access reviews | app example uses document-level permissions; access review revokes un-reviewed grants |

## Phase 3 — Enterprise identity

| Sprint | Work | Exit |
|---|---|---|
| **TS11 MFA and sessions** | TOTP, passkeys, recovery codes, tenant MFA enforcement, step-up (`acr`), session list/revoke, back-channel logout, revocation events, risk signals and notifications | MFA-required tenant cannot be used without MFA; revoked session loses API access within 60 s |
| **TS12 Enterprise SSO** | per-tenant SAML/OIDC connections (Keycloak broker + Ory Polis), guided setup for major IdPs, domain verification, home-realm discovery, JIT and group mapping, SSO-only with break-glass | sign-in via test SAML (e.g. a Keycloak or SimpleSAMLphp IdP in CI) and OIDC IdPs; SSO-only blocks passwords |
| **TS13 SCIM** | SCIM 2.0 per tenant, tokens, users and groups, deprovisioning SLA, conflict handling | Okta/Entra-style SCIM test suite passes; deactivate → sessions revoked < 60 s |

## Phase 4 — Platform and hosting

| Sprint | Work | Exit |
|---|---|---|
| **TS14 Kubernetes install** | Helm charts, `tenantry-operator` (Installation, Tenant CRDs), CNPG, Envoy Gateway + Coraza, cert-manager, ESO, OpenBao HA with auto-unseal, Cilium policies, Kyverno policies | install on kind and one managed cloud from scratch; CIS benchmark passes |
| **TS15 App hosting** | app manifest v1, `tenantry app apply`, TenantApp templates, Argo CD integration, shared and per-tenant instances, Capsule and vCluster tiers, custom domains, release rings with Argo Rollouts | example app deployed as shared and per-tenant instance; canary auto-rollback on injected errors |
| **TS16 Keys and data** | OpenBao transit per tenant, SDK field encryption, BYOK (AWS/GCP/Azure KMS, PKCS#11), crypto-shredding, tenant data export, user export/deletion, retention and legal hold | BYOK revoke makes tenant data unreadable; export round-trips |
| **TS17 Entitlements and metering** | plans, features, limits, SDK checks, OpenMeter integration, usage in consoles, optional Kill Bill module | quota enforcement under concurrency; invoice generated in the billing module test |

## Phase 5 — Scale, resilience, security hardening

| Sprint | Work | Exit |
|---|---|---|
| **TS18 Backups and restore** | Barman Cloud plugin, Velero, OpenBao snapshots, object lock, automated weekly restore tests, single-tenant restore workflow, backup monitoring | restore tests pass in CI and staging; single-tenant PITR restore without affecting others |
| **TS19 Observability** | OpenTelemetry everywhere, VictoriaMetrics, Jaeger, OpenSearch, Perses dashboards, SLOs with burn-rate alerts, status page, support bundle | SLO alerts fire in chaos tests; dashboards per component |
| **TS20 Scale** | Keycloak tuning with external Infinispan, HPA/KEDA, read replicas, cell architecture and tenant directory, load tests to targets (doc 08) | 2,000 sign-ins/s per region with p99 < 300 ms on the reference cluster; documented capacity model |
| **TS21 Multi-region DR** | active-passive replicas (CNPG, Infinispan cross-site, NATS, object storage), `tenantry dr failover`, residency routing, DR game day | failover in staging within RTO 1 h and RPO 15 min |
| **TS22 Security hardening** | threat model review, ASVS L2 checklist, fuzzing, DAST, Falco rules, FIPS profile, compliance mappings and evidence export, third-party penetration test | pen-test criticals and highs fixed; evidence export produces SOC 2 package |

## Phase 6 — 1.0 and adoption

| Sprint | Work | Exit |
|---|---|---|
| **TS23 AgentCanvas on Tenantry** | AgentCanvas uses the SDKs (auth, grants, entitlements, audit forwarding), migrates members and keys, adds workspace columns + RLS to its own tables (AgentCanvas side, planned in its doc 18), deployed as a Tenantry app | AgentCanvas runs on Tenantry in staging with existing data migrated; its cross-tenant suite passes with app checks off |
| **TS24 Docs, air-gap and 1.0** | operator, developer and security docs; air-gapped bundle; upgrade tests; release 1.0 (LTS) | fresh air-gapped install succeeds; 1.0 signed release published |

After 1.0: marketplace, active-active by tenant, Zitadel adapter (plan B), Backstage plug-in, more IdP guides, mobile
SDKs (Swift, Kotlin), foundation submission.

## What changes in AgentCanvas

AgentCanvas's own doc 18 tracks T1–T8 shrink to integration work: T5 (database isolation with workspace columns and
RLS in AgentCanvas tables) stays in AgentCanvas and can start early; the rest becomes TS23 here.
