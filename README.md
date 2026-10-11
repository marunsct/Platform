# Matura

**Make any open-source app enterprise-ready.** Add one SDK and a set of self-hosted services, and your app gets the
multi-tenancy, SSO, access control, audit, backups, privacy and compliance controls business buyers demand, plus
the evidence to prove them. Matura never runs your app and never phones home: everything is open source and stays
on your infrastructure.

> **Status: planning.** Nothing is built yet. Start with the [product definition](docs/plan/16-product-definition.md), then the plan in [`docs/plan/`](docs/plan/README.md) and the decisions in
> [`docs/adr/`](docs/adr/README.md). The first app on Matura will be [AgentCanvas](https://github.com/marunsct/AgentCanvas).
> "Matura" is a working name; the repository is [marunsct/Platform](https://github.com/marunsct/Platform).

## What it gives an app

| You get | Built on |
|---|---|
| Sign-up, sign-in, Google, GitHub and other social logins, passkeys, MFA, password policy, lockout, sessions | Keycloak (Apache-2.0), extended by Matura |
| Tenants, workspaces, invitations, onboarding by email, per-app roles | Matura control plane |
| Fine-grained permissions ("can edit this document") | OpenFGA (Apache-2.0, CNCF) |
| Enterprise SSO per tenant (SAML, OIDC), SCIM directory sync, domain verification | Keycloak identity brokering + Ory Polis (Apache-2.0) |
| Tenant admin console, platform (product) admin console, user account portal | Matura console (React) |
| Tamper-evident audit log, SIEM export | Matura audit service, OpenSearch (Apache-2.0) |
| Secrets and per-tenant encryption keys (BYOK) | OpenBao (MPL-2.0) |
| Usage metering, plans, quotas, entitlements | Matura entitlements + OpenMeter or Kill Bill (Apache-2.0) |
| Backups of your app's data with automatic restore tests | pgBackRest, CloudNativePG, Velero (MIT / Apache-2.0) |
| Readiness: SOC 2 / ISO 27001 / GDPR / HIPAA / EU AI Act control packs, readiness score, continuous evidence, policies, trust page | Matura |
| HA install of Matura itself on Compose or Kubernetes | Kubernetes, CloudNativePG, KEDA, Cilium (Apache-2.0) |
| SDKs for Python, TypeScript/React and Go; CLI; OpenTofu provider | Matura |

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Every bundled component must use an OSI-approved licence; see
[ADR 0002](docs/adr/0002-licence-policy.md).
