# 15 — Market and positioning

> Refined by [doc 16](16-product-definition.md): the product is the enterprise-readiness layer for any open-source app,
> of which the self-hosted WorkOS/Frontegg part is the identity and admin-portal half; doc 16 adds Backup, Privacy and
> Readiness (compliance evidence).

*2026-10-11 · web research; most comparison sources are vendor-written, so treat claims as indicative.*

## 1. Verdict

The idea is valid, but only with a sharper focus than "a platform that does everything".

- **Identity alone is crowded.** Hosted products (Auth0/Okta, WorkOS, Clerk, Frontegg, Descope, Stytch, PropelAuth,
  Kinde) and open-source identity providers (Keycloak, Zitadel, Authentik, Logto, Ory, SuperTokens) already cover
  sign-in, social login, MFA and organisations well. Another login server would not stand out.
- **The real gap is the layer above identity, fully open source and self-hostable.** WorkOS and Frontegg sell the
  customer-facing pieces B2B SaaS teams need (self-service admin portal, per-customer SSO and SCIM setup, audit
  logs, roles, entitlements), but they are hosted and priced per connection or feature tier. Comparisons that
  recommend Keycloak as the open-source WorkOS alternative also say you must "budget for building the customer-facing
  admin portal yourself". The best-known Keycloak organisation extensions moved to a non-open-source licence (ELv2).
  No widely adopted open-source "SaaS control plane" turned up: only young starter kits, a few plans in other
  projects' issue trackers, and older projects with unclear status.
- **App hosting is a second, separate market** (Coolify, Kubero, KubeVela, Backstage-based platforms). Bundling it in
  version 1 widens scope a lot and adds little to the differentiation.

## 2. Positioning to use

**"The open-source WorkOS/Frontegg you can self-host: tenants, customer admin portal, enterprise SSO/SCIM, audit and
entitlements for any app, built on Keycloak."**

| Who | Why they would choose it |
|---|---|
| B2B SaaS teams selling to enterprises | enterprise readiness (SSO, SCIM, audit, admin portal) without per-connection fees |
| Companies that must self-host (EU data sovereignty, finance, health, public sector, on-prem editions) | hosted identity vendors are not an option; Keycloak alone lacks the tenant and admin layer |
| Teams already on Keycloak | add tenants, self-service SSO/SCIM and consoles without ELv2 extensions |
| AI and agent products (like AgentCanvas) | identities for agents and tools, delegated access, MCP/OAuth authorisation, per-tenant audit of agent actions: a fast-growing need in 2026 that most identity products are only starting to address |

## 3. What changes in the plan (adopted by the owner on 2026-10-11; doc 13 updated)

1. **Version 1.0 focus:** identity on Keycloak, tenants and workspaces, the customer admin portal (tenant console)
   with self-service SSO and SCIM, roles and permissions, audit, entitlements, SDKs, Helm/Compose install,
   backups and HA. This is phases 0–3 plus the operational parts of phase 5 in doc 13.
2. **App hosting (doc 06 §2–4) is dropped** (refined further in doc 16: Matura never runs the apps).
3. **Add an "agent identity" track after 1.0:** service identities for AI agents, OAuth token exchange for
   on-behalf-of calls, MCP authorisation server support, consent and audit of agent actions per tenant. AgentCanvas
   is the first user.
4. **Lead with a drop-in story for Keycloak users:** install Matura next to an existing Keycloak and get tenants
   and the admin portal on day one.
5. **Proof points before 1.0:** AgentCanvas running on it, a public demo, migration guides from Auth0/Clerk/Keycloak,
   and a side-by-side feature table against WorkOS and Frontegg.

## 4. Sources

- [5 best WorkOS alternatives (Security Boulevard, 2026)](https://securityboulevard.com/2026/05/5-best-workos-alternatives-for-b2b-saas-teams-that-need-enterprise-sso-in-2026/)
- [Open-source WorkOS alternatives (OpenAlternative)](https://openalternative.co/alternatives/workos)
- [Keycloak vs WorkOS (Skycloak)](https://skycloak.io/blog/keycloak-vs-workos-comparison/)
- [WorkOS alternatives, open-source and self-hosted (Skycloak)](https://skycloak.io/blog/workos-alternatives-developers/)
- [Auth platforms with enterprise SSO (PropelAuth)](https://propelauth.com/post/6-auth-platforms-enterprise-sso-support)
- [Clerk alternatives (Descope)](https://www.descope.com/blog/post/clerk-alternatives)
- [GitHub topic: saas-platform](https://github.com/topics/saas-platform), [sourceplane/multi-tenant-saas](https://github.com/sourceplane/multi-tenant-saas)
- [Phase Two licensing change](https://phasetwo.io/blog/licensing-change/)
