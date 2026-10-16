# Market research: open-source "enterprise-readiness layer" (working name Matura)

Research date: 2026-10-11. Method: web search plus page reads. Every claim has a source URL.
**How much to trust the sources:** much of the pricing and funding data comes from third-party trackers or from competitors' comparison blogs (Logto, SuperTokens, SSOJet, Scalekit, Clerk, WorkOS). Treat those figures as directional and check them on vendor pricing pages before quoting them publicly. Claims backed by only one weak source are marked **(unverified)**.

---

## 0. Executive summary

- **No open-source product bundles the full enterprise-readiness surface.** That surface is SSO, SCIM, an embeddable customer admin portal, audit logs, tenancy, authorization, privacy, readiness evidence and entitlements. A targeted search found pieces only: Keycloak, Zitadel and Ory Polis for identity; Retraced for audit; Comp AI, Probo and CISO Assistant for GRC; Lago and Kill Bill for billing. Nothing bundles an embeddable admin portal with audit logs. https://www.scalekit.com/blog/workos-alternatives , https://idsync.com/alternatives/workos
- **The commercial category is consolidating and moving toward AI agents.** Twilio bought Stytch (Oct–Nov 2025): https://securityboulevard.com/2025/10/the-twilio-stytch-acquisition-a-watershed-moment-for-developer-first-ciam/
  - Vercel bought Better Auth (7 Jul 2026): https://weetracker.com/2026/07/09/better-auth-acquired-vercel-ethiopian-startup/
  - Ory bought BoxyHQ, which became Ory Polis (May 2025): https://www.ory.com/blog/introducing-ory-polis-for-enterprise-single-sign-on
  - Kong bought OpenMeter (Sep 2025): https://konghq.com/blog/news/kong-acquires-openmeter
  - Drata bought SafeBase for about $250M (Feb 2025): https://www.securityweek.com/drata-to-acquire-safebase-in-250-million-deal/amp/
  - CrowdStrike bought Pangea for about $260M (Sep 2025): https://www.govinfosecurity.com/crowdstrike-buys-pangea-for-260m-to-guard-enterprise-ai-use-a-29480
  - WorkOS bought Warrant (FGA, Apr 2024): https://workos.com/blog/workos-acquires-warrant
  - Aserto shut down its SaaS (May 2025): https://www.aserto.com/blog/the-final-chapter-for-aserto
- **Spend signals are large.** Vanta is estimated at about $300M ARR (Apr 2026) with a $4.15B valuation: https://sacra.com/research/vanta-at-300m-year/
  - WorkOS is reportedly at $30M ARR (Oct 2025), with a $100M Series C at a $2B valuation (Mar 2026) **(single source, unverified)**: https://doolpa.com/article/workos , https://www.everydev.ai/developers/workos
- **Two pieces of the planned stack carry ownership risk:**
  - **OpenMeter** is now owned by Kong. Kong says it stays Apache-2.0, but the cloud product was folded into Kong Konnect: https://www.thestack.technology/api-gateway-firm-kong-snaps-up-openmeter/ , https://usagepricing.com/blueprint/activity/openmeter-2025-09-03-kong-acquisition
  - **Keycloak** is strong but costly to operate (see section 4).
- **The 2026 regulatory calendar matters.**
  - The EU AI Act Digital Omnibus (Reg. (EU) 2026/1744, in force 27 Jul 2026) moved Annex III high-risk obligations to **2 Dec 2027** and Annex I to **2 Aug 2028**.
  - Article 50 transparency duties have applied since **2 Aug 2026**.
  - Sources: https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/ , https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes
- **The agent-identity standards have now settled.**
  - The MCP spec 2026-07-28 is final. It moves client registration from DCR to CIMD and adds a stable Enterprise-Managed Authorization extension, built on ID-JAG / Cross App Access: https://praesidia.ai/blog/mcp-2026-spec-revision-stateless-core-cimd , https://agentgateway.dev/blog/2026-08-03-new-mcp-spec-revision/
  - Keycloak 26.2+ supports standard RFC 8693 token exchange: https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2
  - Keycloak also documents MCP authorization-server integration: https://www.keycloak.org/securing-apps/mcp-authz-server

---

## 1. Competitor and adjacent landscape

Module key: **I**=Identity, **T**=Tenancy, **A**=Access/authz, **P**=Admin portal, **Au**=Audit, **B**=Backup, **Pr**=Privacy, **R**=Readiness, **E**=Entitlements/billing.

### 1a. Commercial B2B auth / "enterprise readiness" APIs (closed source, hosted)

| Product | OSS? | Pricing model (2026) | Modules covered | Funding / traction | Weaknesses vs. the plan |
|---|---|---|---|---|---|
| **WorkOS** | No (SDKs only) | AuthKit free to 1M MAU. SSO/SCIM per connection: $125/mo for 1–15, falling to $50/mo for 101–200. Audit Logs $125/mo per SIEM stream plus $99/mo per 1M events. Custom domain $99/mo. Scale support $1,000/mo | I, T (orgs), A (FGA via Warrant), P (Admin Portal), Au, partial R (no GRC) | Reported $100M Series C at $2B (Mar 2026), about $30M ARR, 1,000+ customers incl. OpenAI, Anthropic, Cursor **(unverified)** | Cost grows linearly with enterprise customers: about $6.5k/mo at 100 SSO connections, roughly double with SCIM. Not self-hostable. US-hosted |
| **Frontegg** | No | Sales-led; free to 7,500 MAU | I, T, P (strong embedded admin portal), A (RBAC/entitlements), Au | About $70M raised; $40M Series B (Jul 2022). Launched Frontegg.ai for agents (Apr 2025) and AgentLink MCP (Nov 2025) | Opaque pricing, hosted only |
| **Clerk** | No | Hobby free (50k retained users), Pro $25/mo, Business $300/mo. One enterprise SSO connection included; extra connections about $75/mo **(unverified)** | I, T (orgs), P (components) | Well funded (no 2026 figure confirmed) | Self-serve SSO (Jun 2026) is SAML only, with no self-serve SCIM. Only 3 named IdP integrations versus 20+ at WorkOS |
| **Stytch (Twilio)** | No | Pay-as-you-go: 10k MAU and 5 SSO/SCIM connections free, then $125/connection/mo | I, T, agent OAuth ("Connected Apps") | Acquired by Twilio Nov 2025 (about $104M, unverified) | Product direction now set by a parent company; no volume discount ladder |
| **Descope** | No | Growth $799/mo caps 25k MAU, 100 tenants, 10 SSO; about $50/connection overage **(competitor source)** | I, T, agentic identity hub, MCP auth | $88M total seed (Sep 2025) | Agentic features are new; hosted only |
| **PropelAuth** | No | Free to 10k MAU. Growth $150/mo with unlimited SSO; SCIM possibly on $500/mo tier **(conflicting)** | I, T, P | Small | Hosted only |
| **Kinde** | No | Usage-based; SSO included; SCIM status unclear | I, T, billing-lite | n/a | Hosted only |
| **Auth0 / Okta** | No | B2B Essentials $150/mo (3 enterprise connections), Professional $800/mo (5). Extra connections $100/mo up to 30, then sales | I, T (Orgs), A (Auth0 FGA = OpenFGA), Au (log streams), "Auth0 for AI Agents" | Okta public | Notorious price jumps; enterprise quote-only above about 20–30k MAU |
| **Scalekit** | No | MCP Auth free to 1M users/agents. SSO/SCIM: 1 free, then $60 down to $30 per connection. Agent Auth $2 per 1k connected accounts | I (SSO/SCIM), MCP auth, agent auth | $5.5M seed (2025) | Small; hosted only |

Sources:
- WorkOS pricing: https://ssojet.com/blog/workos-pricing-at-scale-50-100-200-connections , https://idsync.com/guides/workos-pricing , https://itsecureops.com/pricing/workos-pricing/
- WorkOS traction: https://www.everydev.ai/developers/workos
- WorkOS MCP auth: https://workos.com/changelog/mcp-authorization-with-authkit
- Frontegg: https://www.caplight.com/company/frontegg , https://frontegg.com/news , https://ssojet.com/blog/enterprise-authentication-for-developers-10-tools-compared
- Clerk: https://supertokens.com/blog/clerk-pricing-the-complete-guide , https://clerk.com/articles/the-real-cost-of-enterprise-sso-per-connection-vs-per-mau-pricing , https://costbench.com/software/developer-tools/clerk/
- Stytch: https://ssojet.com/blog/7-best-stytch-alternatives-for-b2b-saas-enterprise-auth , https://www.trysignalbase.com/news/acquisitions/stytch-acquired-by-twilio-acquisition , https://static0.twilio.com/en-us/blog/company/news/twilio-to-acquire-stytch
- Descope: https://www.globenewswire.com/news-release/2025/09/30/3158678/0/en/Descope-Extends-and-Closes-Seed-Round-With-88M-Total-Funding-Announces-Advisory-Board.html , https://www.scalekit.com/blog/descope-alternatives
- PropelAuth and Kinde: https://www.propelauth.com/post/6-auth-platforms-enterprise-sso-support , https://toolquestor.com/tr/vs/kinde-vs-propelauth
- Auth0: https://ssojet.com/blog/enterprise-authentication-pricing-2026 , https://clerk.com/articles/the-real-cost-of-enterprise-sso-per-connection-vs-per-mau-p-3
- Scalekit: https://www.scalekit.com/pricing-v6 , https://guptadeepak.com/ciam-compass/vendors/scalekit/

### 1b. Open-source / self-hostable identity

| Product | Licence | Model | Modules | Signals | Weaknesses |
|---|---|---|---|---|---|
| **Keycloak** (CNCF; Red Hat build) | Apache-2.0 | Free. Paid via Red Hat or managed hosts | I (SAML/OIDC, MFA, passkeys); T (Organizations, fully supported since 26.0); token exchange (RFC 8693, 26.2); MCP authz docs; SCIM via extensions; Au (events) | Releases in the 26.x line (26.5 early 2026; 26.7.x referenced) | Operating it is hard: upgrades break themes and SPIs, cluster/cache tuning, memory heavy. Operator survey: 53% cite thin advanced docs, 21% tricky upgrades |
| **Phase Two** | OSS Keycloak extensions plus hosted | Hosted Keycloak with an orgs/admin-portal extension | I, T, P (self-serve SSO setup) | Small | Small vendor; markets itself as a "Keycloak vs WorkOS" alternative |
| **Skycloak** | Hosting for OSS Keycloak | $29/mo dev, $599/mo business (2 clusters), enterprise custom; priced per cluster, not per user | I | n/a | Hosting only |
| **Zitadel** | **AGPL-3.0 from v3** (was Apache). SDKs stay Apache. Commercial licence available | Cloud plus self-host | I, T (multi-tenant by design), event-sourced audit trail, SCIM | $9M Series A (Nov 2024) | AGPL deters embedding; the relicence hurt community trust |
| **Ory** (Kratos, Hydra, Keto, Oathkeeper, Polis) | Apache-2.0 core; **Ory Enterprise License (OEL)** gates Kratos multi-tenancy/orgs, CVE-patched builds, zero-downtime migrations and, per one source, Polis | Ory Network SaaS plus OEL self-hosted | I, A (Keto = Zanzibar), SSO/SCIM (Polis) | Acquired BoxyHQ May 2025 | The open-core gate falls on exactly the B2B features (orgs). The free builds are described as fit only for "deployments that tolerate downtime and skip CVE patching" |
| **Ory Polis** (ex-BoxyHQ SAML Jackson) | Apache-2.0 repo | SSO/SCIM bridge | I (SAML/OIDC SSO, SCIM dir sync) | n/a | Narrow scope |
| **BoxyHQ SaaS Starter Kit** (Ory's "enterprise SaaS starter") | Apache-2.0 | Free boilerplate | I (via Jackson/Polis), Au (Retraced), webhooks (Svix), teams | n/a | Next.js boilerplate you fork, not a maintained layer; steep learning curve |
| **Logto** | MPL-2.0 (OSS core) | Cloud from $16/mo; enterprise SSO $48/connector/mo | I, T (orgs), RBAC, 4 cloud regions | About $4.6M raised **(unverified)** | Weaker for large-enterprise federation and HIPAA/FedRAMP |
| **SuperTokens** | Apache-2.0 core plus paid features | Per MAU; first 5k free; MFA and multi-tenancy are paid even when self-hosted | I, T (paid) | n/a | Paid add-ons inside self-host |
| **Better Auth** (now Vercel) | MIT | Library free. "Infrastructure" dashboard $0/$20/$299 per mo with audit-log retention tiers | I (SSO SAML since 1.3, SCIM since 1.4), T (org plugin), Au (paid infra) | 4.7M weekly npm downloads, 850+ contributors; Vercel acquisition 7 Jul 2026; also maintains Auth.js | TypeScript only; 13 advisories incl. a CVSS 9.1 refresh-token replay; roadmap now set by Vercel |
| **Authentik** | OSS core plus Enterprise licence | Enterprise about $5/user/mo + $0.02/external user **(unverified)**; Enterprise Plus custom (FIPS) | I (workforce-leaning) | n/a | Workforce focus, not B2B multi-tenant SaaS |
| **Hanko** | AGPL plus commercial (sources conflict: MIT/ISC) | Cloud free to 10k MAU, Pro about $99/mo | I (passkey-first) | About $1.5M raised | Narrow |
| **FusionAuth** | Proprietary, free Community edition | $75–$3,300/mo tiers (sources conflict) | I, T (Tenants) | About $65M raised **(unverified)** | Not OSS; SCIM unclear |

Sources:
- Keycloak: https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.0/html-single/release_notes , https://www.cncf.io/blog/2024/11/13/scalable-authentication-across-organizations-with-keycloak-26 , https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2 , https://www.keycloak.org/securing-apps/mcp-authz-server , https://www.keycloak.org/resources/images/blog/distribution-survey-results.pdf , https://skycloak.io/blog/is-self-hosting-keycloak-worth-it-2026/
- Phase Two: https://phasetwo.io/keycloak-alternatives/workos/
- Skycloak: https://skycloak.io/pricing/
- Zitadel: https://zitadel.com/blog/apache-to-agpl , https://zitadel.com/license-faq , https://pulse2.com/zitadel-cloud-native-identity-infrastructure-company-raises-9-million-series-a/amp/
- Ory: https://www.ory.com/docs/self-hosted/oel , https://www.ory.com/ory-enterprise-license , https://ostechnix.com/what-is-ory/
- Ory Polis: https://github.com/ory/polis
- BoxyHQ SaaS Starter Kit: https://github.com/boxyhq/saas-starter-kit , https://www.ory.com/blog/enterprise-ready-saas-starter-kit
- Logto: https://logto.io/compare/workos , https://guptadeepak.com/ciam-compass/vendors/logto/
- SuperTokens: https://helpdesk.supertokens.com/articles/1663201169-supertokens-pricing-for-high-volume-and-enterprise-use-cases
- Better Auth: https://beta.better-auth.com/blog , https://better-auth.com/infrastructure , https://startwithidentity.com/vendors/open-source/better-auth/ , https://dealroom.co/news/137900-vercel-acquires-better-auth-a-year-after-ethiopian-founders-5m-seed/
- Authentik: https://docs.goauthentik.io/enterprise/ , https://aicoolies.com/pricing/authentik
- Hanko: https://guptadeepak.com/ciam-compass/vendors/hanko/ , https://www.hanko.io/blog/hanko-raises-1-2m
- FusionAuth: https://guptadeepak.com/ciam-compass/vendors/fusionauth/ , https://www.spendflo.com/vendors/fusionauth

### 1c. Authorization (Access module)

| Product | Licence | Model | Notes |
|---|---|---|---|
| **OpenFGA** | Apache-2.0, **CNCF Incubating since 28 Oct 2025** | Free; Okta sells Auth0 FGA | 37 public production adopters incl. Docker and Grafana Labs (Grafana engineers are maintainers). Sound foundation choice. https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/ , https://openfga.dev/docs/adopters |
| **SpiceDB / AuthZed** | Apache-2.0 core; AuthZed Cloud/Dedicated | $12M Series A (2024), $15.8M total; customers incl. OpenAI ChatGPT Enterprise connectors; pitching agent and RAG authz | https://www.securityweek.com/authzed-raises-12-million-for-permissions-management-technology/amp/ , https://www.efficientlyconnected.com/?p=5193 , https://techstrong.ai/features/authzed-extends-reach-of-authorization-platform-to-ai-agents/ |
| **Cerbos** | Apache-2.0 PDP plus commercial Hub | Seed-stage (last round 2023) | https://www.cbinsights.com/company/cerbos/financials |
| **Permit.io** | OPAL is OSS; product is SaaS | Hosted policy admin with UI | No funding data found |
| **Aserto / Topaz** | Topaz Apache-2.0, community-maintained | **Aserto SaaS shut down 31 May 2025** ("economics of SaaS model did not work out") | Cautionary tale for authz-as-a-service. https://www.aserto.com/blog/the-final-chapter-for-aserto |
| **Warrant** | Was OSS | Acquired by WorkOS Apr 2024, now WorkOS FGA | https://workos.com/blog/workos-acquires-warrant |

### 1d. Compliance / GRC / readiness (Readiness module)

| Product | OSS? | Pricing | Funding / traction | Notes |
|---|---|---|---|---|
| **Vanta** | No | Entry about $7.5–12k/yr; average contract about $20k/yr. Trust Center add-on about $6k/yr; questionnaire automation $10–25k/yr; questionnaires capped at 25/yr on standard plans | About $300M ARR (Apr 2026), about 16k customers, $4.15B valuation | Market leader |
| **Drata** | No | Quote-based | About $98M ARR (Jan 2025); $2B valuation; owns SafeBase | |
| **Secureframe** | No | About $10–50k/yr; +$7.5k per extra framework | n/a | |
| **Sprinto** | No | About $8–30k/yr | n/a | Reported renewal hikes up to 40% |
| **Oneleet** | No | About $12–60k/yr (bundles pentest and audit) | n/a | |
| **Comp AI** | **AGPLv3** (about 99% of code; small commercial part) | Hosted plus done-for-you | $2.6M pre-seed (Aug 2025, OSS Capital) then $34M Series A (total $36.6M); about 700–1,000+ customers claimed | Trust portal shows only passing controls; device agent; questionnaire module; 270–580 integrations claimed |
| **Probo** | **MIT** (YC) | Free OSS plus done-for-you service | $125k–$3M **(conflicting)** | SOC 2, ISO 27001/27701/**42001**, GDPR, HIPAA; single Go binary |
| **CISO Assistant** (intuitem) | **AGPL-3.0** community; commercial Pro/Enterprise | Self-host Docker | 70–150+ frameworks mapped | Strong framework library |
| **Eramba** | Free Community edition (redistribution and modification reportedly restricted) | Enterprise from about €2,500/yr | Since 2015 | Not really OSS |
| **Delve** (cautionary) | No | n/a | About $32–36M raised | **Alleged fake SOC 2 reports**: 494 of 575 leaked reports had 99.8% identical boilerplate, plus rubber-stamp auditors. YC cut ties; Delve disputes the claims. |

Sources:
- Vanta: https://sacra.com/research/vanta-at-300m-year/ , https://underdefense.com/blog/vanta-pricing/ , https://complyjet.com/blog/vanta-pricing-guide-2025
- Drata: https://sacra.com/c/vanta/ , https://www.premieralts.com/companies/drata/funding-history
- Secureframe, Sprinto, Oneleet: https://soc2auditors.org/insights/secureframe-pricing/ , https://soc2auditors.org/insights/sprinto-pricing/ , https://www.brightdefense.com/resources/secureframe-vs-sprinto/ , https://devtoollab.com/blog/best-soc2-compliance-automation-platforms
- Comp AI: https://www.msspalert.com/brief/comp-ai-raises-34-million-to-advance-ai-powered-compliance-software , https://trycomp.ai/comp-ai-pre-seed-round , https://www.helpnetsecurity.com/2026/04/07/comp-ai-open-source-compliance-platform/ , https://soc2auditors.org/insights/comp-ai-review/
- Probo: https://www.mintlify.com/getprobo/probo/introduction , https://www.ycombinator.com/launches/NaY-probo-open-source-compliance-platform , https://www.startuphub.ai/startups/probo.md
- CISO Assistant: https://github.com/intuitem/ciso-assistant-community , https://www.helpnetsecurity.com/2026/01/14/ciso-assistant-open-source-cybersecurity-management-grc/
- Eramba: https://eramba.org , https://discussions.eramba.org/t/question-installing-community-edition-on-own-server-for-customers/4236
- Delve: https://iansresearch.com/resources/all-blogs/post/security-blog/2026/04/19/delve-allegations-expose-weak-points-in-modern-compliance , https://startupfortune.com/y-combinator-cut-ties-with-delve-after-fake-audit-evidence-surfaced , https://byteiota.com/delve-compliance-fraud-32m-startup-faked-494-soc-2-audits/

**Trust centers and questionnaires:**
- SafeBase was bought by Drata for about $250M (Feb 2025). It raised about $51M before that. https://www.securityweek.com/drata-to-acquire-safebase-in-250-million-deal/amp/ , https://www.cbinsights.com/company/safebase-1
- Conveyor sells AI questionnaire answering plus a trust center. Its funding is reported as $12.5M or $39M by competing sources. https://wolfia.com/blog/safebase-vs-conveyor , https://skypher.co/post/safebase-vs-conveyor-vs-skypher
- **Licensing warning:** the SIG licence reportedly prohibits using SIG content for AI generation, training or benchmarking. Don't ship SIG question text in the repo. https://vorplabs.com/security-framework-changes/sig

### 1e. Audit-log products (Audit module)

- **WorkOS Audit Logs** costs $125/mo per SIEM stream plus $99 per 1M events: https://idsync.com/guides/workos-pricing
- **Retraced** is an OSS audit-log service with an embeddable viewer UI. It came from BoxyHQ and Replicated; after the Ory deal its maintenance status is unclear. https://github.com/retracedhq/retraced
- **Pangea Secure Audit Log** offers tamper-proofing and redaction. Pangea is now part of CrowdStrike and positioned as AI Detection & Response: https://pangea.cloud/docs/audit/ , https://www.sec.gov/Archives/edgar/data/1535527/000153552725000033/crwd-20251031.htm
- **Better Auth Infrastructure** sells audit logs with 1, 7 or 30 day retention tiers: https://better-auth.com/docs/infrastructure/plugins/audit-logs
- **What's left open:** a free, self-hosted, tamper-evident audit log for tenants, with an embeddable viewer and SIEM streaming. Retraced is effectively orphaned and Pangea has gone enterprise.

### 1f. SaaS boilerplates

| Product | Model | Enterprise features |
|---|---|---|
| **SaaS Pegasus** (Django) | One-time $249 / $449 / $999 | Teams/multi-tenancy (Pro+), RBAC. No SAML/SCIM/audit layer. https://saaspegasus.com/pricing |
| **Supastarter** (Next/Nuxt) | Paid licence | Teams/orgs, billing at team level. https://docs.supastarter.dev/nextjs/multi-tenancy |
| **BoxyHQ starter** | Apache-2.0 | SSO, SCIM, audit, webhooks. See 1b |
| **Nhost** | OSS BaaS; Pro $25/mo | No clear enterprise SSO found. https://toolradar.com/tools/nhost/pricing |
| **Supabase** (reference) | SSO/SAML only on Team ($599/mo) or Enterprise | Itself an example of the SSO tax. https://www.jetadmin.io/blog/supabase-pricing-2026-guide-to-plans-limits-and-real-world-costs/ |

**The weakness these share:** a boilerplate is forked once and then goes stale. Nobody ships updated SCIM edge cases or new IdP quirks into your fork. A maintained SDK-plus-services layer avoids that.

### 1g. Billing and metering (Entitlements module)

| Product | Licence | Status / model |
|---|---|---|
| **Lago** | AGPL-3.0 core; Premium is commercial | $22M raised. Premium was consolidated in Jul 2026 and can now be self-hosted (quote only). https://sacra.com/c/lago/ , https://usagepricing.com/blueprint/activity/lago-2026-07-22-premium-package-consolidation |
| **OpenMeter** | Apache-2.0 | **Acquired by Kong (3 Sep 2025)**. Cloud migrated into Konnect Metering & Billing by mid-2026. Kong promises the OSS stays Apache-2.0; 2026 repo activity unverified. https://konghq.com/company/press-room/press-release/kong-acquires-openmeter-to-unlock-ai-and-api-monetization-for-the-agentic-era , https://usagebox.com/articles/openmeter-alternatives-2026 |
| **Kill Bill** | Apache-2.0 (Java) | Active (about 188 commits in 12 months to Aug 2026) but spread over many repos with heavy plugin overhead. https://ideaproof.io/open-source/project/kill-bill , https://us.fitgap.com/products/kill-bill |
| **Flexprice** | OSS (licence not confirmed) | $500k pre-seed (Jul 2025), $1.5M seed (May 2026). Go, ClickHouse, Kafka, Temporal; AI-usage billing; claims 20B events/mo. https://startuptalky.com/news/flexprice-raises-1-5m-seed-round-led-by-shastra-vc-with-participation-from-tdv-partners-and-anupam-mittal/ |
| **Stripe Billing** | Proprietary | 0.7% of billing volume (raised from 0.5% in 2025); 0.4% for one-off invoices. https://usagebox.com/articles/stripe-billing-fees-2026-the-07-percent-math , https://polar.sh/polarsource/polar/issues/3665 |

**Coverage:** no competitor covers all 9 modules. WorkOS comes closest on modules 1–5 but has no tenancy data plane, backup, privacy, readiness or billing. The Vanta-class tools cover Readiness only, and they assess your controls rather than ship them.

---

## 2. Buyer side: what security reviews and procurement demand (2025–2026)

### 2a. Baseline asks for B2B SaaS
- **SOC 2 Type II** is the default expectation. Procurement increasingly rejects Type I from mature vendors, and buyers also ask for bridge letters, trust-center access or custom questionnaires even when you have a report. Only about 7% of companies with under $1M in funding are SOC 2 compliant. https://www.privaxi.com/blog/soc-2-in-2026-the-report-your-enterprise-deals-now-depend-on , https://www.brightdefense.com/resources/soc-2-for-startups
- **SSO (SAML/OIDC) and SOC 2 Type II** are the two most consistent hard blockers. SCIM and audit-log retention come close behind. https://securityboulevard.com/2026/04/9-critical-security-questionnaire-items-that-stall-enterprise-saas-deals/
- **Audit logs** must be queryable and exportable to Splunk or Sentinel without a project, not merely generated. Reviewers also probe how fast access is revoked, which is really a SCIM deprovisioning question. https://startwithidentity.com/articles/b2b-saas-enterprise-readiness/ , https://hashorn.com/blog/enterprise-ready-saas-sso-scim-audit-logs
- **Questionnaires:**
  - SIG 2026 (released Sep 2025) has 21 domains, including a **dedicated AI domain mapped to ISO 42001 and NIST AI RMF**. It is also mapped to CAIQ 4.0. Corporate licence about $7k/yr. https://vorplabs.com/security-framework-changes/sig
  - CSA CAIQ v4 maps to the Cloud Controls Matrix (no 2026 AI text found).
- **The SSO tax as a policy issue:**
  - CISA's Jun 2024 report found SMB SSO adoption held back by cost and tiering, and urged vendors to change practices: https://cisa.gov/resources-tools/resources/barriers-single-sign-sso-adoption-small-and-medium-sized-businesses-identifying-challenges-and
  - sso.tax keeps the "Wall of Shame"; HubSpot SSO costs 6,300% more, for example: https://sso.tax/press , https://www.ory.com/blog/sso-wall-of-shame-vs-wall-of-fame
  - 1Password's take on the backlash: https://1password.com/blog/explaining-the-backlash-to-the-sso-tax

### 2b. Data residency and sovereignty
- EU buyers are moving from *residency* ("data in Frankfurt") to *sovereignty*: who controls the operator, given CLOUD Act exposure.
- The EU Data Act Ch. VII has applied since 12 Sep 2025.
- The Commission's Cloud Sovereignty Framework scores providers on 48 criteria across 8 areas.
- **A self-hosted layer that runs inside the app vendor's or customer's EU infrastructure fits this trend directly.**
- Sources: https://www.buildmvpfast.com/blog/data-sovereignty-vs-residency-eu-procurement-2026 , https://cyso.cloud/blog/digital-sovereignty-eu-cloud-rules-2026 , https://www.theregister.com/2026/01/30/euro_firms_must_ditch_us/

### 2c. EU regulation timeline
- **EU AI Act** (after the Omnibus, Reg. 2026/1744, in force 27 Jul 2026):
  - GPAI obligations have applied since Aug 2025.
  - Art. 50 transparency has applied since 2 Aug 2026, with a grace period to 2 Dec 2026 for machine-readable marking of systems already on the market.
  - New Art. 5 prohibitions start 2 Dec 2026.
  - Annex III high-risk obligations start **2 Dec 2027**; Annex I starts **2 Aug 2028**.
  - Sources: https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/ , https://usercentrics.com/knowledge-hub/eu-ai-act-high-risk-delay-article-50-transparency-consent/ , https://www.alpacax.com/blog/eu-ai-act-high-risk-deadline-moved-to-2027-what-didnt/
- **Logging and human oversight duties** that the Audit module can serve:
  - Art. 12: providers must build in automatic event logging for the system's lifetime.
  - Art. 26: deployers keep those logs for **at least 6 months**.
  - Art. 14: humans must be able to detect anomalies, override and stop the system. A bare approval prompt is not enough.
  - Sources: https://presencis.com/regulations/eu-ai-act/conformity/article-12-record-keeping , https://www.stackone.com/blog/eu-ai-act-action-layer-logs/
- **DORA:**
  - Financial entities keep a Register of Information on ICT third parties (second annual submission closed Mar 2026). 19 critical ICT providers are under direct EU oversight.
  - Vendors must give continuous evidence of security, incident and BCP controls.
  - One argument worth checking with counsel: **self-hosted software, with no vendor-operated control plane, is not a third-party ICT dependency in the same sense.** https://blog.openvpn.net/dora-nis2-cra-vendor-risk-network-access , https://labs.cloudsecurityalliance.org/research/csa-research-note-gdpr-nis2-dora-third-party-risk-convergenc/
- **NIS2:** Art. 21(2)(d) supply-chain security reaches software suppliers through contracts. https://www.rescana.com/learn/compliance/nis2-supply-chain/
- **ISO/IEC 42001:**
  - It is turning into the "SOC 2 for AI" in questionnaires; there are anecdotes of 60-question AI questionnaires decided by "ISO 42001 certified".
  - Certification typically takes 6–12 months and $45–130k from scratch, less if you already run ISO 27001 (consultancy figures).
  - Sources: https://tarrysingh.com/blog/the-certificate-you-did-not-list , https://www.bdemerson.com/article/iso-42001-certification-path

### 2d. Specific asks for AI and agent products (relevant to AgentCanvas)
- **MCP authorization:**
  - The 2025-11-25 spec made CIMD the preferred registration path and DCR optional: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization , https://aaronparecki.com/2025/11/25/1/mcp-authorization-spec-update
  - The **2026-07-28** spec has a stateless core. It deprecates DCR in favour of CIMD (with a deprecation window), adds `iss` in authorization responses, binds credentials to the issuer, and makes **Enterprise-Managed Authorization (EMA)** a stable extension (stable 18 Jun 2026) so the enterprise IdP (Okta, Entra) governs which MCP servers employees reach. It also adds unattended-agent options: https://praesidia.ai/blog/mcp-2026-spec-revision-stateless-core-cimd , https://agentgateway.dev/blog/2026-08-03-new-mcp-spec-revision/ , https://stacktr.ee/blog/mcp-2026-spec-changes
- **ID-JAG / Cross App Access** (IETF draft; Okta calls it "XAA"):
  - Leg 1 is RFC 8693 token exchange at the IdP, allowed only if admin policy permits. Leg 2 is an RFC 7523 JWT-bearer grant at the resource's authorization server.
  - It moves consent from end users to IT admins, which is what makes headless agents governable.
  - Sources: https://workos.com/blog/id-jag-cross-app-access , https://docs.litellm.ai/docs/mcp_id_jag , https://www.descope.com/learn/post/id-jag-cross-app-access
- **Agent identity as a principal:**
  - NIST NCCoE concept paper "Software and AI Agent Identity and Authorization" (5 Feb 2026). It covers identification, authorization, auditing, non-repudiation and prompt-injection controls, and looks at MCP, OAuth 2.1, OIDC, SPIFFE, SCIM and NGAC: https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf
  - OWASP Top 10 for Agentic Applications (Dec 2025) includes ASI03 Identity & Privilege Abuse, ASI07 Insecure Inter-Agent Communication and ASI10 Rogue Agents: https://www.token.security/blog/owasp-top-10-and-the-identity-first-security-imperative-for-autonomous-ai-agents , https://auth0.com/blog/owasp-top-10-agentic-applications-lessons/
- **Vendors already selling agent auth:** WorkOS (AuthKit as MCP authorization server), Auth0 for AI Agents, Stytch Connected Apps, Descope Agentic Identity Hub, Frontegg AgentLink, Scalekit Agent Auth, Better Auth "Agent Auth" (now inside Vercel). Agent auth is now baseline, not a differentiator. https://mcp.directory/blog/auth0-vs-clerk-vs-workos-vs-stytch-vs-descope-mcp-2026
- **Human-in-the-loop logging:** EU AI Act Art. 14 and Art. 12/26 imply logs of who approved or overrode which agent action, keyed to the delegating human and the agent principal and kept at least 6 months. AuthZed is also pitching "restrict which tools an agent reaches, plus audit logs". https://techstrong.ai/features/authzed-extends-reach-of-authorization-platform-to-ai-agents/

---

## 3. Developer pain evidence

- **The cost of per-connection pricing at scale:**
  - About $6.5k/mo for SSO alone at 100 WorkOS connections, roughly double with SCIM.
  - Audit Logs and SIEM add $125 per stream.
  - A Jan 2024 HN thread on WorkOS pricing is referenced, but its contents weren't retrieved.
  - Sources: https://ssojet.com/blog/workos-pricing-at-scale-50-100-200-connections , https://supertokens.com/blog/workos-alternatives
- **Price-tier jumps:** Auth0 enterprise connections were historically around "$30,000/yr for up to 10", which fed the "Auth0 too expensive for B2B" complaints: https://community.auth0.com/t/auth0-too-expensive-for-b2b-scenario/57335
- **Self-host pain:** setting up Keycloak is easy; running it in production is a full-time job. Every IdP formats claims differently, which makes SSO hard to maintain. https://skycloak.io/blog/is-self-hosting-keycloak-worth-it-2026/ , https://www.ssdnodes.com/learn/the-sso-tax-in-self-hosted-apps
- **Open-core frustration:**
  - Ory gates orgs and multi-tenancy behind OEL, and calls its free builds unsuitable when you need CVE patching: https://www.ory.com/docs/self-hosted/oel
  - SuperTokens bills MFA even when self-hosted: https://helpdesk.supertokens.com/articles/1663201169-supertokens-pricing-for-high-volume-and-enterprise-use-cases
  - Zitadel relicensed to AGPL: https://zitadel.com/blog/apache-to-agpl
- **Lost deals:** "a founder spends six months … deal dies in security review. Nothing was wrong with the product." https://www.privaxi.com/blog/soc-2-in-2026-the-report-your-enterprise-deals-now-depend-on
- **The other side of the argument:** Gergely Orosz argues companies *should* charge more for non-standard SSO because it is real extra work. That supports pricing support and services rather than gating the feature. https://www.ssdnodes.com/learn/the-sso-tax-in-self-hosted-apps
- **Evidence gap:** searches didn't surface first-party HN or Reddit threads. Before positioning, validate with 15–20 founder interviews and an HN "Ask HN" post.

---

## 4. Gaps, opportunities and risks

### 4a. Gaps nobody covers well
1. **One OSS layer with an embeddable customer admin portal plus audit plus SSO/SCIM.** Confirmed missing: https://www.scalekit.com/blog/workos-alternatives
2. **Self-hosted, tamper-evident tenant audit log with SIEM streaming and a viewer component.** Retraced is orphaned; Pangea went to CrowdStrike.
3. **Controls that are actually implemented, linked to evidence.** GRC tools such as Vanta or Comp AI *check* controls by integrating with AWS, GitHub and similar. None *ship* the application-level controls (tenant isolation, audit, SSO enforcement, DSAR, backups and restore tests) and emit evidence automatically. This is the most differentiated idea in the plan. Make Readiness the evidence emitter, not a full GRC suite.
4. **Agent-native tenant governance for AI apps:** MCP authorization server, EMA/ID-JAG acceptance, per-tenant agent principals in OpenFGA, and HITL approval logs mapped to AI Act Art. 12/14/26 and ISO 42001 Annex A. Hosted vendors cover parts of this; no OSS covers it end to end.
5. **Privacy operations inside the app** (DSAR export/delete, crypto-shredding with per-tenant keys). OneTrust-class tools do this from outside the app; nothing OSS does it in-app.
6. **Restore-test evidence.** Auditors ask for proof that restores work. CloudNativePG and pgBackRest do backups, but nobody turns a restore test into SOC 2 CC9 / ISO A.8.13 evidence.
7. **Sovereignty:** Apache-2.0, self-hosted and EU-deployable answers sovereignty scoring and the DORA third-party argument (section 2c).

### 4b. Risks
- **Keycloak operations** (heavy JVM, theme and SPI breakage on upgrades, clustering): https://skycloak.io/blog/is-self-hosting-keycloak-worth-it-2026/ , https://www.keycloak.org/resources/images/blog/distribution-survey-results.pdf
  - Mitigations: pin and test Keycloak versions, ship an operator or Helm chart, avoid custom SPIs where possible, put an abstraction in the SDK, and let users bring an existing IdP.
- **Compliance liability.** The Delve allegations show that "compliance in a box" claims attract scrutiny: https://iansresearch.com/resources/all-blogs/post/security-blog/2026/04/19/delve-allegations-expose-weak-points-in-modern-compliance
  - Never claim to make a company compliant. Say "controls plus evidence; your auditor decides."
  - Don't generate auditor conclusions. Keep policy templates as templates, with disclaimers.
  - Comp AI's trust portal shows only passing controls; copy that honesty.
- **Scope too wide.** Nine modules is a WorkOS-plus-Vanta-plus-Lago surface area. Aserto's failure shows that standalone authz SaaS economics are hard: https://www.aserto.com/blog/the-final-chapter-for-aserto
- **Dependency ownership churn:**
  - OpenMeter is now Kong's; the cloud product is gone and OSS longevity is unproven.
  - Ory Polis is now under an open-core vendor.
  - Better Auth is now Vercel's.
  - Kill Bill is Java with a small team.
  - Mitigation: adapter interfaces for every third-party engine.
- **Open-core sustainability.** Rug-pull relicences (HashiCorp, then OpenTofu; Zitadel to AGPL) erode trust. Apache-2.0 is a differentiator only if the business model doesn't need to gate core features later. https://thenewstack.io/rip-open-core-long-live-open-source/ , https://zitadel.com/blog/apache-to-agpl
- **Hosted giants keep moving down-market and adding free tiers.** AuthKit is free to 1M MAU; Scalekit offers MCP Auth free and $30–60 connections. The pricing gap narrows on identity alone; the moat has to come from the bundle plus self-hosting.
- **Security exposure.** An auth layer is a high-value target. Better Auth had 13 advisories incl. a CVSS 9.1 issue: https://startwithidentity.com/vendors/open-source/better-auth/ . The project needs a security policy, a bug bounty and signed releases from day one.

### 4c. Sustainable business models (evidence-based)
| Model | Precedent | Fit |
|---|---|---|
| Paid "enterprise builds" with CVE SLAs, LTS and zero-downtime migrations (code stays OSS) | Ory OEL https://www.ory.com/docs/self-hosted/oel ; Red Hat build of Keycloak | **High.** Sells to the people the product makes enterprise-ready. Gate *operations*, not features |
| Managed operator / "we run it in your cloud" (BYOC) | Skycloak $29–$599/mo per cluster https://skycloak.io/pricing/ | High. Keeps "never hosts the app", since only the layer is run, in the customer's account |
| Support plus readiness services (done-for-you SOC 2, auditor network) | Probo, Comp AI, Oneleet https://www.startuphub.ai/startups/probo.md | Medium. Revenue now, but services-heavy; auditor independence must be kept |
| Paid content packs (control mappings, policy libraries, questionnaire answer banks) | CISO Assistant Pro, Vanta add-ons | Medium. Watch SIG licensing |
| Hosted trust page / questionnaire portal (small SaaS add-on) | SafeBase was worth about $250M to Drata | Medium-high. A small hosted surface that doesn't host the app |
| Open core (gating SSO, SCIM, orgs) | Ory, SuperTokens, Lago, Zitadel | **Avoid.** It recreates the SSO tax you are fighting |
| Fair-source / FSL | Sentry, Keygen https://keygen.sh/blog/keygen-is-now-fair-source/ | Not compatible with the Apache-2.0 promise. Keep it in reserve only for a separate commercial console |

2026 commentary says revenue is shifting to managed hosting, support, compliance tooling and migration, and buyers expect SBOMs and signed releases: https://blog.mean.ceo/?p=10989

---

## 5. Recommendations to improve the plan

### 5a. Positioning
- **Lead with: "The open-source WorkOS you self-host, with controls that produce their own evidence."** "Enterprise-readiness layer" is accurate but abstract. Anchor against WorkOS pricing (per connection, hosted) and Vanta (which checks controls but doesn't implement them).
- **Make the wedge "AI and agent apps selling to enterprise".** AgentCanvas is the reference app. The buyer asks for agent apps (EMA/ID-JAG, CIMD, agent principals, HITL logs, ISO 42001, the AI domain in SIG 2026) are fresh, standards-driven and badly served by OSS.
- **Use EU sovereignty and DORA as the second wedge.** Self-hosted plus Apache-2.0 helps EU-selling SaaS and fintech suppliers.

### 5b. Features to add
1. **MCP authorization server profile:** CIMD client registration, DCR only as legacy, RFC 9728 metadata, `iss` binding and step-up. Build it on Keycloak 26.2+ token exchange.
2. **Accept EMA / ID-JAG:** customers' Okta or Entra decide which agents may call the app.
3. **Agent principals as first-class tenant members:** SCIM-provisionable, revocable, with OpenFGA relations like `agent#acts_for@user` and per-tool scopes.
4. **HITL approval and override log schema** mapped to AI Act Art. 12/14/26, with at least 6 months retention by default.
5. **OCSF-formatted audit events** plus push-to-customer destinations (S3/GCS bucket, Splunk HEC, Sentinel, Datadog) and an embeddable log viewer React component.
6. **Self-serve SSO/SCIM setup wizard** in the customer admin portal, with per-IdP guides for Okta, Entra, Google, JumpCloud, Ping and OneLogin, domain verification, and a **Mock IdP / SAML test harness** for CI (BoxyHQ had Mock SAML).
7. **Webhooks/events bus** for tenant lifecycle and SCIM events. The BoxyHQ starter used Svix; offer a built-in or adapter.
8. **Restore-test evidence:** scheduled restore of CNPG/pgBackRest backups into an ephemeral cluster, checksum checks, and a signed evidence record.
9. **Evidence export in OSCAL and JSON** to Vanta, Drata, Comp AI, Probo and CISO Assistant. **Integrate with the GRC tools, don't compete with them.**
10. **Pre-filled answers for SIG Lite and CAIQ v4.** Store the answers, not the question text, because of SIG licensing. Add a generated "security whitepaper" PDF.
11. **`readiness doctor` CLI** that scores an app's posture in CI and opens PRs for gaps. A strong developer-adoption hook.
12. **BYOK / per-tenant KMS** (AWS KMS, GCP KMS, Vault) to support crypto-shredding and "customer-managed keys", a frequent enterprise ask.

### 5c. Features to cut or defer
- **Defer billing via Kill Bill.** Billing is a separate domain with deep competition (Stripe, Lago, Flexprice). Keep **entitlements plus feature flags plus usage-limit checks** in core and ship adapters to Stripe Billing, Lago and OpenMeter. Kill Bill adds a JVM and a second heavy operational component on top of Keycloak.
- **Don't hard-depend on OpenMeter** (Kong ownership). Put metering behind an interface; a Postgres or ClickHouse counter covers v1.
- **Narrow Readiness v1** to SOC 2 plus ISO 27001 plus ISO 42001, with AI Act Art. 12/14/26 logging. Leave HIPAA, the full GDPR program and a broad framework library to CISO Assistant or Comp AI integrations.
- **Make the trust page minimal.** A static, generated, self-hostable page is enough; offer a hosted version as the paid add-on.
- **Make the operator console optional.** Ship the customer self-service portal first; that is what buyers see.

### 5d. Wedge, first users, adoption
- **First users:** seed-to-Series-B AI-agent and devtool startups facing their first enterprise security review, especially in the EU. Fintech suppliers are an early target because of DORA.
- **Distribution:**
  - One-command `docker compose` and Helm installs.
  - Next.js/FastAPI/Go/Java SDKs.
  - "Add SSO plus SCIM plus audit to your app in 30 minutes" tutorials.
  - Starter templates for Better Auth, Auth.js and Clerk migrators: Better Auth is now in Vercel's orbit, and WorkOS is already running "migrate from Better Auth" content (https://workos.com/blog/vercel-acquires-better-auth-migrate-to-workos).
  - A public "cost vs WorkOS at N connections" calculator.
  - A listing on sso.tax's Wall of Fame-style pages.
- **Credibility:**
  - Get the project's own SOC 2 or a third-party pentest, published SBOMs, signed releases and a security.txt.
  - Consider donating the audit-event schema or MCP-authz pieces to a foundation such as CNCF or OpenSSF, as OpenFGA did.
- **Naming:** pick a name that is trademark-clear in Class 9/42 and owns the `.dev` domain plus the GitHub org. (Name conflicts were not researched here.)

---

## Top 15 recommendations

1. **Position as "open-source, self-hosted WorkOS plus evidence-producing controls"**, with a cost calculator against WorkOS ($125 down to $50 per connection plus audit streams).
2. **Make the wedge AI and agent apps selling to enterprise**, with AgentCanvas as the live reference app.
3. **Ship MCP 2026-07-28 authorization first-class:** CIMD, EMA / ID-JAG acceptance, RFC 8693 token exchange (Keycloak 26.2+), issuer binding.
4. **Model agents as revocable, SCIM-provisionable tenant principals in OpenFGA**, with per-tool scopes and on-behalf-of chains.
5. **Build HITL approval and override audit events mapped to EU AI Act Art. 12/14/26**, retained at least 6 months, ready for the 2 Dec 2027 Annex III date and for ISO 42001.
6. **Make Audit a standalone hero module:** tamper-evident (hash chain), OCSF schema, SIEM and bucket streaming, embeddable viewer. This fills the gap left by Retraced and Pangea.
7. **Make the self-serve SSO/SCIM admin portal the primary UI**, with IdP guides, domain verification and a mock-IdP CI harness. Defer the operator console.
8. **Have Readiness emit evidence, not run GRC.** Export OSCAL and JSON to Vanta, Drata, Comp AI, Probo and CISO Assistant. Never claim compliance (the Delve lesson).
9. **Limit Readiness v1 to SOC 2, ISO 27001 and ISO 42001**, plus SIG Lite and CAIQ answer banks (answers only, because of SIG licensing).
10. **Cut Kill Bill from v1.** Keep entitlements and limits in core with Stripe, Lago and OpenMeter adapters; abstract metering because of Kong's ownership.
11. **Hide Keycloak's complexity:** pinned and tested versions, an operator or Helm chart, no fragile custom SPIs, upgrade CI, and a "bring your own IdP" mode.
12. **Add restore-test evidence and BYOK / per-tenant KMS.** These are concrete auditor and enterprise asks that nobody in OSS automates.
13. **Keep everything Apache-2.0 with no feature gating.** Earn money from enterprise builds (CVE SLAs and LTS, the Ory OEL model applied to operations only), BYOC managed operations (Skycloak-style), and a hosted trust page and questionnaire portal.
14. **Pitch EU sovereignty and DORA:** self-hosted means no vendor control plane. Target EU SaaS and fintech suppliers as a second segment.
15. **Earn trust from day one:** the project's own pentest or SOC 2, SBOMs and signed releases, a bug bounty, a `readiness doctor` CLI as the growth loop, and 15–20 founder interviews to validate pain before broad launch.
