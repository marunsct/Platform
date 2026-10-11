# Tenantry

**The open-source WorkOS/Frontegg you can self-host, built on Keycloak. A platform for running multi-tenant apps:** sign-up and sign-in, tenants and
workspaces, roles and fine-grained permissions, enterprise SSO and SCIM, audit, admin consoles, billing hooks and
app hosting. It is built only from open-source components, under a permissive licence, so anyone can host their own
suite of apps on it.

> **Status: planning.** Nothing is built yet. Read the plan in [`docs/plan/`](docs/plan/README.md) and the decisions in
> [`docs/adr/`](docs/adr/README.md). The first app on Tenantry will be [AgentCanvas](https://github.com/marunsct/AgentCanvas).
> "Tenantry" is a working name; the repository is [marunsct/Platform](https://github.com/marunsct/Platform).

## What it gives an app

| You get | Built on |
|---|---|
| Sign-up, sign-in, Google, GitHub and other social logins, passkeys, MFA, password policy, lockout, sessions | Keycloak (Apache-2.0), extended by Tenantry |
| Tenants, workspaces, invitations, onboarding by email, per-app roles | Tenantry control plane |
| Fine-grained permissions ("can edit this document") | OpenFGA (Apache-2.0, CNCF) |
| Enterprise SSO per tenant (SAML, OIDC), SCIM directory sync, domain verification | Keycloak identity brokering + Ory Polis (Apache-2.0) |
| Tenant admin console, platform (product) admin console, user account portal | Tenantry console (React) |
| Tamper-evident audit log, SIEM export | Tenantry audit service, OpenSearch (Apache-2.0) |
| Secrets and per-tenant encryption keys (BYOK) | OpenBao (MPL-2.0) |
| Usage metering, plans, quotas, entitlements | Tenantry entitlements + OpenMeter or Kill Bill (Apache-2.0) |
| HA install, autoscaling, backups, multi-region; optional app hosting after 1.0 | Kubernetes, CloudNativePG, Argo CD, KEDA, Velero, Cilium (all Apache-2.0) |
| SDKs for Python, TypeScript/React and Go; CLI; OpenTofu provider | Tenantry |

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Every bundled component must use an OSI-approved licence; see
[ADR 0002](docs/adr/0002-licence-policy.md).
