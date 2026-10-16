# 13 — Roadmap

Sprints are numbered `TS1…` (Matura sprint) to stay apart from AgentCanvas sprints. Each sprint ends with tests
green, docs updated, a changelog entry and a tagged pre-release. Exit criteria are checked by automated tests where
possible.

Product definition: doc 16. Performance: doc 17. UI: doc 18. Research-driven changes: doc 19.

**Alongside phase 0:** interview 15–20 founders of AI and B2B apps facing their first enterprise security review, to
confirm the order of modules before phase 2 starts (doc 19 §2.13).

## Phase 0 — Foundation

| Sprint | Work | Exit |
|---|---|---|
| **TS1 Repository and stack** | repo layout, CI (lint, test, licence check, SBOM, cosign signed releases, security.txt), ADRs 0001–0005 accepted, licence audit of every component (`deps/licences.yaml`), Compose stack (Keycloak 26 pinned, Postgres, PgBouncer, Valkey, NATS, OpenFGA, OpenBao dev, SeaweedFS, ClickHouse, Mailpit, Temporal), realm-as-code, docs site skeleton, benchmark harness skeleton | `docker compose up` brings every component healthy; CI green with licence gate |
| **TS2 Control plane skeleton** | `maturad` with tenants, workspaces, users, memberships, apps, grants; Postgres schema with RLS (doc 17 §2.8: `set_config` in first statement, tenant-leading indexes, UUIDv7, fail closed); idempotency keys; transactional outbox → JetStream with de-duplication; OpenAPI and generated clients; audit with per-tenant hash chains, Merkle batches and signed checkpoints in OCSF format; Temporal worker skeleton | API and cross-tenant tests pass; `matura audit verify` passes; outbox delivers exactly once under a crash test |
| **TS3 Design system and app shell** | doc 18: DTCG tokens → Style Dictionary → Tailwind 4; OKLCH theme generator with contrast tests and per-tenant `theme.css`; `packages/ui` on Base UI; Vite + TanStack Router/Query app shell with view transitions, light/dark/density; command palette; DataTable; Lingui with RTL; fonts; Storybook with screenshot regression; axe, size-limit and Lighthouse CI gates | shell and components pass the a11y, size and visual gates; a sample tenant theme renders in light, dark and RTL |

## Phase 1 — Identity

| Sprint | Work | Exit |
|---|---|---|
| **TS4 Sign-in and sign-up** | Keycloakify theme on `packages/ui` (≤ 60 KB JS, LCP ≤ 1 s), passkey-first (conditional mediation, passkey nudge), sign-up with email verification, Google and GitHub brokering, first-sign-in choice (shared tenant + personal workspace, or new company tenant), forgot/reset password, password policy and breached-password mirror, lockout | Playwright: sign up, verify, sign in, passkey, reset password, social login against a mock OIDC provider; Lighthouse budgets met |
| **TS5 Keycloak extensions** | lightweight tokens < 2 KB with tid, wid, roles; event listener → NATS → audit; temporary-password required action with expiry; verify-alternate-address action; tenant-scoped admin endpoints; Keycloak upgrade test job (themes and extensions against the next minor) | extension tests green; tokens carry correct claims for a user in two tenants; upgrade job green |
| **TS6 Onboarding and invitations** | invite by email with link or temporary password, deliver-to-other-address, bulk CSV, resend/revoke/expire, email outbox with templates, SMTP settings, tenant creation with owner | Playwright: admin onboards a user by temporary password, forced change, correct roles; expired temp password refused |
| **TS7 SDKs and embeddables v0** | Python, TypeScript and Go SDKs: local token verification with verified-token cache, settings and entitlement snapshots pushed over NATS KV (ETag feed fallback), permission decision cache, RLS helper, audit emit; micro-benchmarks gating every PR; `@matura/react` (provider, `UserButton`, `OrgSwitcher`, `MembersTable`) and `@matura/elements` with the `appearance` API; example FastAPI + React app | example works end to end with two tenants; SDK token check p99 < 1 ms; app keeps serving with the control plane stopped |

## Phase 2 — Customer portal and permissions

| Sprint | Work | Exit |
|---|---|---|
| **TS8 Customer admin portal I** | members, invitations, groups, workspaces, apps, roles (incl. custom roles), API keys and service accounts; optimistic updates | tenant owner completes every members/roles task without the API; INP ≤ 150 ms |
| **TS9 Customer admin portal II** | sessions, security policies (MFA required, methods, sessions, IP allow-list), audit viewer with live tail and export, audit streaming destinations (S3/GCS, Splunk HEC, Sentinel, Datadog, syslog), webhooks, branding editor with live preview, My account (replaces Keycloak account console) | policy changes reach SDKs within 5 s; audit export matches the chain; a stream delivers to a test SIEM |
| **TS10 Operator console** | tenant lifecycle (create, suspend, delete with grace and crypto-shred), users across tenants, shared-tenant controls, plans and entitlements, support access with consented impersonation, security centre v1; reuses portal components | impersonation requires approval, shows a banner, expires, appears in both audit logs |
| **TS11 Fine-grained permissions** | OpenFGA integration, app authorisation models from manifests, check/batch/list APIs, per-tenant revision numbers for read-your-writes, "who has access" views, access reviews | app example uses document-level permissions; a grant change is visible to the SDK on the next check; access review revokes un-reviewed grants |

## Phase 3 — Enterprise and agent identity

| Sprint | Work | Exit |
|---|---|---|
| **TS12 MFA and sessions** | TOTP, passkeys, recovery codes, tenant MFA enforcement, step-up (`acr`), session list/revoke, back-channel logout, revocation events, risk signals and notifications | MFA-required tenant cannot be used without MFA; revoked session loses API access within 60 s |
| **TS13 Enterprise SSO** | self-serve SSO wizard in the portal with guides for Okta, Entra, Google, JumpCloud, Ping and OneLogin; per-tenant SAML/OIDC (Keycloak broker + Ory Polis); domain verification; home-realm discovery; JIT and group mapping; SSO-only with break-glass; **mock SAML/OIDC IdP** app developers can run in CI | a tenant admin connects a test SAML and OIDC IdP without help; SSO-only blocks passwords |
| **TS14 SCIM** | SCIM 2.0 per tenant (evaluate Keycloak 26.7 SCIM API against Ory Polis), tokens, users and groups, deprovisioning SLA, conflict handling, mock SCIM client for CI | Okta/Entra-style SCIM test suite passes; deactivate → sessions revoked < 60 s |
| **TS15 Agent identity** | MCP authorisation per the 2026-07-28 spec (Client ID Metadata Documents, protected-resource metadata, issuer binding, step-up); accepting customer-IdP-issued agent grants; RFC 8693 token exchange for on-behalf-of calls; agents as revocable, SCIM-provisionable tenant members in OpenFGA with per-tool scopes; consent screens; kill switch; human-approval and override audit events mapped to EU AI Act articles 12, 14 and 26 with ≥ 6 months retention; SDK helpers | an AgentCanvas-style agent calls a tool on a user's behalf with a scoped token, the action and approval show in the tenant's audit log, and revoking consent stops it within 60 s |

## Phase 4 — Install, keys and entitlements

| Sprint | Work | Exit |
|---|---|---|
| **TS16 Kubernetes install, drop-in and bring-your-own IdP** | Helm charts, `matura-operator` (Installation, Tenant CRDs), CNPG with PgBouncer poolers, Envoy Gateway (native filters) + Coraza, cert-manager, ESO, OpenBao HA with auto-unseal, Cilium and Kyverno policies; **drop-in mode** next to an existing Keycloak; **bring-your-own IdP** mode for any OIDC provider (reduced features, documented) | install on kind and one managed cloud from scratch; CIS benchmark passes; an existing Keycloak realm gains tenants and the portal without migration |
| **TS17 Keys and data** | OpenBao transit per tenant, SDK field encryption, customer-managed keys (AWS/GCP/Azure KMS, PKCS#11), crypto-shredding, tenant data export, user export/deletion, retention and legal hold | revoking a customer key makes tenant data unreadable; export round-trips |
| **TS18 Entitlements** | plans, features, flags (OpenFeature), limits; SDK checks from snapshots and quota leases (p99 < 50 µs); usage pre-aggregated in the SDK; metering interface with a built-in ClickHouse counter; billing adapters for Stripe Billing, Lago and OpenMeter | quota holds under concurrency; usage reaches a Stripe test account through the adapter |

## Phase 5 — Backup, scale, resilience, hardening

| Sprint | Work | Exit |
|---|---|---|
| **TS19 Backup module** | works with or without Kubernetes: pgBackRest for Compose/VM installs and CloudNativePG + Barman Cloud plugin on Kubernetes, for Matura's databases **and the app's** (Postgres + object storage); Velero, OpenBao snapshots, object lock; automated weekly restore tests into an ephemeral cluster with checksums, each producing a **signed evidence record**; single-tenant restore; backup monitoring | restore tests pass in CI and staging and emit evidence; single-tenant PITR restore without affecting others |
| **TS20 Observability** | OpenTelemetry everywhere, VictoriaMetrics, Jaeger, ClickHouse for logs and audit search, Perses dashboards, SLOs from doc 17 with burn-rate alerts, real-user Web Vitals from the consoles, status page, support bundle | SLO alerts fire in chaos tests; dashboards per component |
| **TS21 Performance and scale** | doc 17: separate Keycloak login and token pools, cache tuning, HPA/KEDA, read replicas, cell architecture and tenant directory, per-tenant fair queues and load shedding; load tests with k6, keycloak-benchmark, `nats bench`, ghz, Nighthawk to the doc 17 SLO table; nightly 25% and weekly full-scale, soak, spike, noisy-neighbour and chaos runs; results published | doc 17 SLOs met on the reference cluster (10k logins/s, 100k permission checks/s, 50k audit events/s); control-plane outage chaos test shows no app impact |
| **TS22 Multi-region DR** | active-passive replicas (CNPG, Infinispan cross-site within metro, NATS, object storage), `matura dr failover`, residency routing, DR game day | failover in staging within RTO 1 h and RPO 15 min |
| **TS23 Security hardening** | threat model review, ASVS L2 checklist, fuzzing, DAST, Falco rules, FIPS profile, bug bounty launch, third-party penetration test of Matura itself | pen-test criticals and highs fixed; report summary published |

## Phase 6 — Readiness, proof and 1.0

| Sprint | Work | Exit |
|---|---|---|
| **TS24 Readiness I: controls and evidence** | control packs (SOC 2, ISO 27001, ISO 42001, GDPR, EU AI Act logging and oversight) mapped to module settings; `matura check` readiness score with gap → fix links, runnable in CI and able to open fix pull requests; continuous evidence (MFA coverage, SSO/SCIM status, access reviews, audit integrity, restore tests, vulnerability scans, change history); export as OSCAL and JSON for Vanta, Drata, Comp AI, Probo and CISO Assistant; wording never claims compliance | `matura check` lists every gap with its fix on a sample install; fixing them raises the score; an evidence package imports into one GRC tool |
| **TS25 Readiness II: documents and trust** | policy templates filled from configuration (marked as templates), static prerendered trust page (doc 18), answer banks for SIG Lite and CAIQ v4 (answers only), generated security whitepaper, readiness views in both consoles | a generated policy set and questionnaire match the install's real settings; trust page meets doc 18 budgets |
| **TS26 AgentCanvas on Matura** | AgentCanvas adopts Identity, Tenancy (workspace columns + RLS on its tables, its doc 18 T5), Access, Admin portal, Audit forwarding, Agent identity, Backup, Privacy and the AI readiness pack; migrates members and keys; keeps its own deployment | AgentCanvas runs on Matura in staging with data migrated; its cross-tenant suite passes with app checks off; `matura check` shows SOC 2 and ISO 42001 controls met except organisational ones |
| **TS27 Adoption kit and 1.0** | public demo; migration guides and import tools from Auth0, Clerk, Better Auth and plain Keycloak; cost calculator against WorkOS; comparison against WorkOS, Frontegg and Vanta/Drata; quick-starts for FastAPI, Django, Express, Next.js, Go; operator, developer and security docs; accessibility conformance report; air-gapped bundle; upgrade tests; release 1.0 (LTS) | fresh air-gapped install succeeds; each migration works on sample data; 1.0 signed release published |

**Version 1.0 = TS1–TS27:** the nine modules of doc 16 plus agent identity, SDKs and embeddable widgets, Compose and
Helm install (also drop-in next to an existing Keycloak, or with your own IdP), the performance targets of doc 17
measured and published, the UI standard of doc 18, HA and DR for Matura itself, a third-party penetration test, and
AgentCanvas running on it.

## After 1.0 — optional modules

| Module | Work | Exit |
|---|---|---|
| **M1 More control packs** | HIPAA, PCI DSS SAQ helpers, NIST 800-53, NIS 2, DORA, CSA STAR | per pack |
| **M2 Active-active by tenant, Zitadel adapter, Backstage plug-in, mobile SDKs** | doc 08 §4, ADR 0001 plan B, doc 05 §4, Swift/Kotlin | per module |
| **M3 Local-first consoles** | TanStack DB or ElectricSQL once they reach 1.0 (doc 18 §3.10) | offline edits sync without conflicts in tests |

App hosting is dropped: Matura never runs the apps (doc 16 §2). Kill Bill is no longer planned; billing goes through
adapters (TS18).

## What changes in AgentCanvas

AgentCanvas's own doc 18 tracks T1–T8 shrink to integration work: T5 (database isolation with workspace columns and
RLS in AgentCanvas tables) stays in AgentCanvas and can start early; the rest becomes TS26 here.
