# 19 — Research findings and plan changes

*2026-10-11 · deep research on market, buyers, performance and UI after the owner asked to improve the plan on all
fronts. Full research with sources: [research/market.md](../research/market.md),
[research/performance.md](../research/performance.md), [research/ui.md](../research/ui.md),
[research/name.md](../research/name.md). Pricing and funding figures come largely from third-party trackers; check
vendor pages before quoting them.*

## 1. What the research confirmed

- **The gap is real.** No open-source product bundles SSO, SCIM, an embeddable customer admin portal and audit logs,
  let alone tenancy, privacy, readiness and entitlements. WorkOS comes closest but is hosted and charges about $50–125
  per SSO or SCIM connection per month plus $125 per audit-log stream.
- **The open-source alternatives gate or restrict B2B features:** Zitadel moved to AGPL, Ory keeps multi-tenancy in
  its paid enterprise licence, SuperTokens charges for self-hosted MFA, and Comp AI, CISO Assistant and Lago are AGPL.
  Apache-2.0 with nothing gated stands out.
- **The market is consolidating:** Twilio bought Stytch, Vercel bought Better Auth, Ory bought BoxyHQ (now Ory Polis),
  Kong bought OpenMeter, Drata bought SafeBase, CrowdStrike bought Pangea, WorkOS bought Warrant. Independent,
  vendor-neutral open source is getting scarcer.
- **What buyers block on:** SOC 2 Type II and SSO most consistently, then SCIM and exportable, SIEM-streamable audit
  logs. SIG 2026 adds an AI section mapped to ISO 42001, which is becoming "SOC 2 for AI".
- **AI regulation is now dated:** EU AI Act transparency duties apply from 2 August 2026 and high-risk (Annex III)
  duties from 2 December 2027; deployers keep system logs at least six months and human oversight must be real.
- **Agent authorisation has standardised:** the MCP specification dated 2026-07-28 uses Client ID Metadata Documents
  instead of dynamic client registration and lets a customer's own identity provider govern which agents reach an
  app. Every hosted identity vendor already sells agent auth; no open-source project covers it end to end.
- **EU buyers increasingly ask who controls the operator**, not only where data sits. Self-hosted with no vendor
  control plane is a strong answer for EU SaaS and DORA-regulated suppliers (to be confirmed with counsel).
- **Compliance claims carry liability:** a compliance startup was accused in 2026 of producing near-identical SOC 2
  reports. Matura produces controls and evidence; it never claims to make anyone compliant.
- **Keycloak is the right base** (Organizations, token exchange, an MCP authorisation-server guide, SCIM API preview in
  26.7) but costly to operate: upgrades break themes and extensions. OpenFGA is a safe choice (CNCF incubating, used by
  Docker and Grafana).

## 2. Changes adopted in the plan

| # | Change | Where |
|---|---|---|
| 1 | Product renamed **Matura** (Latin "ripe": prototype to market-ready) | doc 14 decision 2, everywhere |
| 2 | **Agent identity moves into 1.0** as its own sprint: MCP authorisation (2026-07-28 spec, Client ID Metadata Documents, protected-resource metadata), acceptance of customer-IdP-issued agent grants, RFC 8693 token exchange on Keycloak, agents as revocable, SCIM-provisionable tenant members in OpenFGA with per-tool scopes, consent and kill switch, human-approval and override log events mapped to EU AI Act articles 12, 14 and 26 | doc 13 TS15 |
| 3 | **Audit becomes a headline module:** OCSF event schema, push destinations (S3/GCS bucket, Splunk HEC, Microsoft Sentinel, Datadog, syslog), embeddable viewer, per-tenant chains with signed checkpoints (doc 17) | doc 13 TS2, TS9, TS20 |
| 4 | **Readiness emits evidence and integrates with GRC tools** instead of competing with them: export in OSCAL and JSON to Vanta, Drata, Comp AI, Probo and CISO Assistant; restore-test results signed as evidence | doc 13 TS24 |
| 5 | **Readiness 1.0 scope:** SOC 2, ISO 27001, ISO 42001, GDPR, EU AI Act logging and oversight. HIPAA moves after 1.0. Questionnaire answer banks for SIG Lite and CAIQ store answers only (SIG licensing) | doc 13 TS24–TS25, M1 |
| 6 | **`matura check` runs in CI** and suggests fixes as pull requests: the developer growth loop | doc 13 TS24 |
| 7 | **Kill Bill dropped from 1.0.** Entitlements, feature flags and limits stay in core; billing through adapters (Stripe Billing, Lago, OpenMeter); metering behind an interface with a built-in ClickHouse counter, because OpenMeter's owner changed | doc 13 TS18 |
| 8 | **Self-serve SSO/SCIM wizard is the portal's centrepiece**, with guides for Okta, Entra, Google, JumpCloud, Ping and OneLogin, domain verification, and a mock SAML/OIDC/SCIM identity provider for app developers' CI | doc 13 TS13–TS14 |
| 9 | **Performance plan** (doc 17): the app never waits on Matura; SDK checks in microseconds; SLO table; a dedicated performance sprint with published results | doc 13 TS21 |
| 10 | **UI plan** (doc 18): design system sprint first, passkey-first sign-in, white-label themes with enforced contrast, embeddable widgets, quality gates | doc 13 TS3 and UI sprints |
| 11 | **ClickHouse replaces OpenSearch as the default** audit search and analytics store (shared with metering); OpenSearch optional | doc 17 §2.9 |
| 12 | **Hide Keycloak's complexity:** pinned and upgrade-tested versions, few custom extensions, "bring your own IdP" mode alongside drop-in | doc 13 TS5, TS16 |
| 13 | **Validate before building:** interview 15–20 founders of AI and B2B apps facing their first enterprise security review, in parallel with phase 0 | doc 13 phase 0 |
| 14 | **Earn trust from day one:** signed releases, SBOMs, security.txt, bug bounty, Matura's own third-party penetration test before 1.0 | doc 13 TS1, TS23 |

Not adopted: making the operator console optional. Operators need it for tenant lifecycle and support, so it stays,
but it ships after the customer portal and reuses all of its components.

## 3. Positioning

**"Matura: the open-source, self-hosted way to make your app enterprise-ready. SSO, SCIM, tenants, audit, backups and
compliance evidence, Apache-2.0, nothing gated."**

- Wedge 1: **AI and agent apps selling to enterprises**, with AgentCanvas as the live reference app.
- Wedge 2: **EU SaaS and fintech suppliers** that need sovereignty and DORA-friendly self-hosting.
- Anchor comparisons: WorkOS (hosted, per connection) for the identity half, Vanta/Drata (check controls, don't add
  them) for the readiness half. Publish a cost calculator against WorkOS.

## 4. Sustaining the project

Everything stays Apache-2.0 with no feature gating; gating SSO or SCIM would recreate the "SSO tax" Matura exists to
remove. Options that fit, for the owner to choose later:

1. Enterprise builds: long-term-support releases, security-patch SLAs and assisted upgrades (code stays open).
2. Running Matura inside a customer's own cloud account as a managed service (the app is still never hosted).
3. A small hosted trust page and questionnaire portal.
4. Readiness content packs and services through partner auditors, keeping auditor independence.
