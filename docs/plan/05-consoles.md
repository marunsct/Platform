# 05 — Consoles

All consoles are one React application with four areas, built from the shared UI kit (`@matura/react`), themable
per installation and per tenant (logo, colours, custom domain), light and dark, keyboard accessible (WCAG 2.2 AA),
translated (i18n from day one). Every action calls the public or admin API, so anything in a console is also
scriptable.

## 1. Tenant admin console (tenant `owner`, `admin`, `security_admin`, `billing`, `auditor`)

| Area | Features |
|---|---|
| Overview | members, seats used, apps enabled, security score (MFA coverage, SSO status, stale accounts), recent events |
| Members | search, filter (role, status, last sign-in, MFA), add by email (link or temporary password, other address), bulk CSV, change tenant and app roles per workspace, suspend, remove, transfer ownership, sign out everywhere, reset MFA (four-eyes option) |
| Invitations | pending, resend, revoke, edit roles, expiry |
| Groups | local, SCIM and IdP groups; group-to-role mapping |
| Workspaces | create, rename, archive, delete; per-workspace members and roles; residency shown |
| Apps | enable/disable apps for the tenant; per-app settings the app exposes; per-app roles and custom roles |
| Access review | "who can access what" per app and object; scheduled access reviews (quarterly) with sign-off and auto-revoke for un-reviewed access |
| Security policies | MFA required (all / admins), allowed sign-in methods, password policy, session idle and max, IP allow-list, allowed countries, personal access tokens on/off, support access on/off |
| Single sign-on | add SAML/OIDC connection (guided per IdP), test, certificate expiry, domain verification, JIT and group mapping, "SSO only" |
| Directory sync | SCIM connections and tokens, last sync, errors |
| Service accounts and API keys | create, scope, expire, rotate, last used |
| Sessions | all members' sessions, revoke |
| Audit log | filter by actor, action, target, result, time; export CSV/JSON; stream to SIEM (syslog, HTTPS, S3, Splunk HEC-compatible, OpenSearch) |
| Webhooks | endpoints, events, deliveries, replay |
| Usage and billing | plan, seats, metered usage per app, invoices, payment method (if billing module on), quota alerts |
| Encryption | key status, rotate, BYOK setup, key access log |
| Data | export tenant data, retention settings, legal hold, delete tenant (typed confirmation, grace period) |
| Branding | logo, colours, login page text, email templates, custom domain with automatic TLS |

## 2. Platform admin console (installation operators)

| Area | Features |
|---|---|
| Dashboard | tenants, users, sign-ups per day, active users, errors, SLO burn, open incidents, capacity |
| Tenants | search, create (onboard owner), plan and limits, isolation tier, region, suspend, reactivate, delete, move tier or region, notes, tags |
| Users | search across tenants, lock/unlock, force password reset, revoke sessions, see tenants and roles, merge duplicates |
| Shared tenant | members, abuse queue (reports, risk flags), sign-up mode, blocked domains |
| Apps | register apps from manifests, versions, which tenants use them, roll-outs per ring (internal, beta, general) |
| Plans and entitlements | plans, features, limits, trials, overrides per tenant |
| Support access | requests, approvals, active impersonations, history |
| Security center | failed sign-ins, lockouts, credential stuffing, impossible travel, admin actions, MFA resets, policy violations, Falco runtime alerts |
| Audit | platform staff actions, tamper check status, exports |
| Email and messaging | outbox, bounces, complaints, domain authentication (SPF/DKIM/DMARC) status |
| Feature flags | per tenant, per app, percentage roll-outs (OpenFeature/flagd) |
| Infrastructure | regions, clusters, database health, backup status and last restore test, certificate expiry, version and upgrade |
| Compliance | control status (doc 07), evidence export, sub-processors, data maps |
| Settings | identity providers available to tenants (Google, GitHub client ids), SMTP, branding, legal documents, maintenance windows, status page |

Platform admin access requires MFA with passkeys, a separate admin hostname, optional IP allow-list, and short
sessions (15 min idle).

## 3. Account portal (every user)

Profile, email change (verify both), password, passkeys and authenticators, recovery codes, sessions and devices,
connected accounts (Google, GitHub), tenants and workspaces I belong to, invitations, personal access tokens, privacy
(export my data, delete my account), notification preferences, language and theme.

## 4. Developer portal (app builders)

Register an app (manifest editor with validation), OIDC client settings and redirect URIs, roles and permission
model (OpenFGA model editor with tests), API keys for development tenants, webhook tester, event catalogue,
SDK quick-starts, API reference (from OpenAPI), sandbox tenant with seed data, usage of their app across tenants
(platform admins only), release rings. Optional Backstage plug-in for companies that already run Backstage.

## 5. Login and sign-up pages

Keycloak pages themed with Keycloakify from the same design tokens: sign-in, sign-up, verify email, forgot and reset
password, update password, MFA enrol and challenge, passkey, first-sign-in choice, select tenant, SSO discovery
(email first), terms, error pages. Per-tenant branding on custom domains. Accessibility and localisation as above.
