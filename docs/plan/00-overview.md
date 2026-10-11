# 00 — Overview and decision

> Read [doc 16, the product definition](16-product-definition.md), first. This document explains the build-versus-adopt
> decision behind it.

## 1. Short answer

- **No single open-source product does all of this today.** There are excellent open-source *parts*: identity
  providers (Keycloak, Zitadel, Authentik, Logto, Ory, Casdoor), authorisation engines (OpenFGA, SpiceDB), SSO
  bridges (Ory Polis), billing (Kill Bill, OpenMeter, Lago), and a complete cloud-native stack for hosting, backup
  and scale (Kubernetes, CloudNativePG, Argo CD, Velero, OpenBao…). What is missing is the **control plane that turns
  them into a multi-tenant app platform**: tenants, workspaces, per-app roles, onboarding, entitlements, the admin
  consoles, the SDKs and the operator that installs and runs it all. Starter kits exist (SaaS boilerplates), but
  they are app templates, not platforms others can host.
- **So we adopt, extend and assemble, and build only the missing layer.** Keycloak is the identity core, used
  unforked and extended through its plug-in interfaces (SPIs). Around it Matura adds the control plane, consoles,
  SDKs, a Kubernetes operator and Helm charts. Every piece is open source; our own code is Apache-2.0.
- **"Improving on it" concretely means** open-source Keycloak extensions where today's options are closed or
  source-available: per-tenant roles, per-tenant SCIM and SSO self-service, temporary-password onboarding with
  expiry, tenant-aware admin APIs and themes. The best-known Keycloak organisation extensions (Phase Two) moved to
  the Elastic License v2, which is not open source, so there is a real gap to fill.
- **Enterprise suite is in scope from the start:** SSO (SAML/OIDC per tenant), SCIM, MFA and passkeys, session
  control, tamper-evident audit, per-tenant encryption keys, data residency, row-level isolation up to dedicated
  databases and clusters, autoscaling, multi-region, point-in-time backups and tested restores, SLOs, and SOC 2 /
  ISO 27001 / GDPR / HIPAA-ready controls (doc 07).

## 2. Why build on Keycloak, not on another identity provider

| Option | Licence | For | Against | Verdict |
|---|---|---|---|---|
| **Keycloak** | Apache-2.0 (CNCF incubating, Red Hat backed) | most complete feature set (OIDC, SAML, LDAP/AD, brokering, MFA, passkeys, fine session control); Organizations since 25/26; documented multi-site HA; huge install base; permissive licence lets others host and modify freely | Java, heavier to run; per-organisation roles and per-organisation SCIM are thin; admin UI is not tenant-friendly; themes need tooling | **Chosen core.** Its gaps are exactly what Matura adds |
| Zitadel | AGPL-3.0 since v3 (SDKs Apache-2.0) | best native multi-tenancy, modern login, event-sourced audit | AGPL: anyone who modifies it and serves it must publish changes; that limits a platform meant to be embedded and resold; our extensions would have to be AGPL too | Strong alternative; kept as plan B behind the SDK boundary |
| Authentik | MIT core, enterprise features source-available | friendly UI, flows, outposts | key enterprise features (e.g. some audit/compliance) sit in a non-open-source directory; multi-tenancy basic | Not chosen |
| Logto | MPL-2.0 | developer-friendly, Organizations, SAML apps | younger, smaller enterprise footprint (LDAP, federation, multi-site HA) | Not chosen; good reference for UX |
| Ory (Kratos, Hydra, Keto, Oathkeeper, Polis) | Apache-2.0 | headless, cloud-native, scales well | assemble-it-yourself; some enterprise pieces (SAML/SCIM built into Kratos) are in the commercial licence; no admin console | Use **Ory Polis** only (SAML/SCIM bridge) |
| Casdoor | Apache-2.0 | built-in multi-org, Casbin policies | smaller community, security track record thinner | Not chosen |
| Write our own | ours | full control | we would own password storage, MFA, SAML, recovery, session revocation: each a security product | Rejected |

## 3. What we build (the missing layer)

1. **Control plane** (`maturad`, Go): tenants, workspaces, memberships, app registry, per-app roles, invitations
   and onboarding, entitlements and quotas, audit, webhooks and events, SCIM fan-out, domain verification, data
   export and deletion. Drives Keycloak, OpenFGA, Ory Polis and OpenBao through their APIs.
2. **Keycloak extensions** (Java, Apache-2.0): tenant-aware token mapper (tenant, workspace, app roles), onboarding
   required-actions (temporary password with expiry, verify alternate email), event listener to the control plane,
   tenant-scoped admin endpoints, themes built from our design tokens (Keycloakify).
3. **Consoles** (React/TypeScript): tenant admin, platform admin, account portal, developer portal (doc 05).
4. **SDKs**: Python, TypeScript, React UI kit, Go; plus a CLI and an OpenTofu/Terraform-compatible provider (doc 11).
5. **Operator and charts**: a Kubernetes operator (`matura-operator`) and Helm charts that install and run the
   whole platform, manage tenants' dedicated resources (silo tier), backups and upgrades; a Docker Compose bundle for
   small installs and evaluation.
6. **App hosting layer**: app manifests, per-tenant app instances, deploy pipeline (doc 06).

## 4. Principles

- **Open source only.** OSI-approved licences for everything we ship or require; no BSL, SSPL, ELv2 or "open core"
  dependencies for required features (ADR 0002). Permissive preferred; copyleft services allowed only unmodified and
  replaceable.
- **Upstream first.** Use projects unforked; contribute fixes upstream; extend through supported plug-in points.
- **Secure by default.** MFA available on day one, RLS on by default, least privilege, everything audited.
- **Same code from laptop to hyperscale.** Compose for evaluation, one Kubernetes cluster for small production, multi-
  cluster multi-region for large, with the same images and APIs.
- **Apps stay decoupled.** Apps talk to Matura only through OIDC, the SDKs and documented APIs, never its database.

## 5. Scope of version 1.0

See **doc 16 (product definition)**, which supersedes the earlier wording here: Matura makes any open-source app
enterprise-ready through nine self-hosted modules (Identity, Tenancy, Access, Admin portal, Audit, Backup, Privacy,
Readiness, Entitlements) and an SDK. It is not a PaaS and does not run the apps. Roadmap: doc 13.
