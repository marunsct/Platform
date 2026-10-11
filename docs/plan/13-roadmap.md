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

## Phase 4 — Install, keys and entitlements

| Sprint | Work | Exit |
|---|---|---|
| **TS14 Kubernetes install and Keycloak drop-in** | Helm charts, `tenantry-operator` (Installation, Tenant CRDs), CNPG, Envoy Gateway + Coraza, cert-manager, ESO, OpenBao HA with auto-unseal, Cilium and Kyverno policies; **drop-in mode**: connect Tenantry to an existing Keycloak (realm import, organisation sync, extensions installed as a JAR) instead of installing a new one | install on kind and one managed cloud from scratch; CIS benchmark passes; an existing Keycloak realm with users gains tenants and the admin portal without migration |
| **TS15 Keys and data** | OpenBao transit per tenant, SDK field encryption, BYOK (AWS/GCP/Azure KMS, PKCS#11), crypto-shredding, tenant data export, user export/deletion, retention and legal hold | BYOK revoke makes tenant data unreadable; export round-trips |
| **TS16 Entitlements and metering** | plans, features, limits, SDK checks, OpenMeter integration, usage in consoles, optional Kill Bill module | quota enforcement under concurrency; invoice generated in the billing module test |

## Phase 5 — Scale, resilience, security hardening

| Sprint | Work | Exit |
|---|---|---|
| **TS17 Backup module** | works with or without Kubernetes: pgBackRest agent for Compose/VM installs and CloudNativePG + Barman Cloud plugin on Kubernetes, for Tenantry's own databases **and the app's** (Postgres + object storage/files); Velero, OpenBao snapshots, object lock, automated weekly restore tests, single-tenant restore workflow, backup monitoring | restore tests pass in CI and staging; single-tenant PITR restore without affecting others |
| **TS18 Observability** | OpenTelemetry everywhere, VictoriaMetrics, Jaeger, OpenSearch, Perses dashboards, SLOs with burn-rate alerts, status page, support bundle | SLO alerts fire in chaos tests; dashboards per component |
| **TS19 Scale** | Keycloak tuning with external Infinispan, HPA/KEDA, read replicas, cell architecture and tenant directory, load tests to targets (doc 08) | 2,000 sign-ins/s per region with p99 < 300 ms on the reference cluster; documented capacity model |
| **TS20 Multi-region DR** | active-passive replicas (CNPG, Infinispan cross-site, NATS, object storage), `tenantry dr failover`, residency routing, DR game day | failover in staging within RTO 1 h and RPO 15 min |
| **TS21 Security hardening** | threat model review, ASVS L2 checklist, fuzzing, DAST, Falco rules, FIPS profile, third-party penetration test | pen-test criticals and highs fixed |

## Phase 6 — Readiness, proof points and 1.0

| Sprint | Work | Exit |
|---|---|---|
| **TS22 Readiness I: controls and evidence** | control packs (SOC 2, ISO 27001, GDPR, HIPAA, EU AI Act logging/oversight) mapped to module settings; `tenantry check` readiness score with gap → fix links; continuous evidence collection (MFA coverage, SSO/SCIM status, access reviews, audit integrity, backups and restore tests, vulnerability scans, change history); auditor export | on a sample install `tenantry check` lists every gap with its fix; fixing them raises the score; the SOC 2 evidence package exports with timestamps |
| **TS23 Readiness II: documents and trust** | policy templates filled from configuration, public trust page, pre-filled security questionnaire answers (CAIQ / SIG Lite style), readiness view in the platform and tenant consoles | a generated policy set and questionnaire match the install's real settings; trust page renders |
| **TS24 AgentCanvas on Tenantry** | AgentCanvas adopts Identity, Tenancy (workspace columns + RLS on its tables, its doc 18 T5), Access, Admin portal, Audit forwarding, Backup, Privacy and the AI readiness pack; migrates members and keys; keeps its own deployment | AgentCanvas runs on Tenantry in staging with existing data migrated; its cross-tenant suite passes with app checks off; `tenantry check` on AgentCanvas shows SOC 2 controls met except organisational ones |
| **TS25 Adoption kit and 1.0** | public demo; migration guides and import tools from Auth0, Clerk and plain Keycloak; comparison against WorkOS, Frontegg and Vanta/Drata; integration quick-starts for FastAPI, Django, Express, Next.js, Go; operator, developer and security docs; air-gapped bundle; upgrade tests; release 1.0 (LTS) | fresh air-gapped install succeeds; each migration works on sample data; 1.0 signed release published |

**Version 1.0 = TS1–TS25:** the nine modules of doc 16 (Identity, Tenancy, Access, Admin portal, Audit, Backup,
Privacy, Readiness, Entitlements), SDKs, Compose and Helm install (also as a drop-in next to an existing Keycloak),
HA and DR for Tenantry itself, a security review, and AgentCanvas running on it. Product definition: doc 16.

## After 1.0 — optional modules

| Module | Work | Exit |
|---|---|---|
| **M1 Agent identity (first module after 1.0)** | identities for AI agents and tools as first-class principals; OAuth 2 token exchange (RFC 8693) for on-behalf-of calls with scoped, short-lived tokens; MCP authorisation server support (OAuth 2.1, dynamic client registration, resource indicators); user consent screens for agent access; per-tenant audit and kill switch for agent actions; SDK helpers | an AgentCanvas agent calls a tool on a user's behalf with a scoped token, the action shows in the tenant's audit log, and revoking consent stops it within 60 s |
| **M2 More control packs** | PCI DSS SAQ helpers, NIST 800-53, NIS 2, DORA, CSA STAR | per pack |
| **M3 Active-active by tenant, Zitadel adapter, Backstage plug-in, mobile SDKs** | doc 08 §4, ADR 0001 plan B, doc 05 §4, Swift/Kotlin | per module |

App hosting (earlier "M2") is dropped: Tenantry never runs the apps (doc 16 §2).

## What changes in AgentCanvas

AgentCanvas's own doc 18 tracks T1–T8 shrink to integration work: T5 (database isolation with workspace columns and
RLS in AgentCanvas tables) stays in AgentCanvas and can start early; the rest becomes TS24 here.
