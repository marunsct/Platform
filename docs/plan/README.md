# Tenantry plan

*2026-10-11 · proposed, waiting for the owner's approval.*

**Start with [16 — Product definition](16-product-definition.md).**

| # | Document | What it covers |
|---|---|---|
| 00 | [Overview and decision](00-overview.md) | The short answer: what exists in open source, what we adopt, what we build, and why |
| 01 | [Open-source landscape](01-landscape.md) | Every candidate project per area, with licence, fit and verdict |
| 02 | [Architecture](02-architecture.md) | Components, data model, APIs, events, deployment shapes |
| 03 | [Identity and access](03-identity-and-access.md) | Sign-up, sign-in, onboarding by email, social login, MFA, sessions, SSO, SCIM, roles, fine-grained permissions, API keys |
| 04 | [Multi-tenancy and isolation](04-multi-tenancy-and-isolation.md) | Tenant model, isolation tiers, database row-level security, Kubernetes tenancy, keys per tenant, data residency |
| 05 | [Consoles](05-consoles.md) | Tenant admin console, platform admin console, user account portal, developer portal |
| 06 | [Integrating apps](06-app-hosting.md) | The app manifest and how an app plugs in (hosting dropped, see doc 16) |
| 07 | [Security and compliance](07-security-and-compliance.md) | Threat model, controls, encryption, secrets, supply chain, audit, SOC 2 / ISO 27001 / GDPR / HIPAA readiness |
| 08 | [Scale, availability, backup and disaster recovery](08-scale-ha-dr.md) | Hyperscaling, high availability, multi-region, backups, restore drills, RPO/RTO |
| 09 | [Observability and operations](09-observability-and-operations.md) | Metrics, logs, traces, SLOs, alerting, upgrades, runbooks, status page |
| 10 | [Billing, metering and entitlements](10-billing-and-entitlements.md) | Plans, quotas, usage metering, invoices |
| 11 | [Developer experience](11-developer-experience.md) | SDKs, CLI, APIs, webhooks, OpenTofu provider, local development |
| 12 | [Running the open-source project](12-open-source-project.md) | Licence policy, governance, releases, security disclosure, community |
| 13 | [Roadmap](13-roadmap.md) | Phases and sprints with exit criteria; moving AgentCanvas onto Tenantry |
| 14 | [Risks and open decisions](14-risks-and-decisions.md) | What could go wrong and what the owner decides |
| 15 | [Market and positioning](15-market-and-positioning.md) | Is this a real gap? Competitors, where we stand out, and the narrower 1.0 focus |
| 16 | [Product definition](16-product-definition.md) | **Start here.** The vision, the nine modules, the Readiness module, competitors, what AgentCanvas needs |

Decisions: [`../adr/`](../adr/README.md).
