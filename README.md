# Matura

**Make any open-source app enterprise-ready.** Add one SDK and a set of self-hosted services, and your app gets the
multi-tenancy, SSO, access control, audit, backups, privacy and compliance controls business buyers demand, plus
the evidence to prove them. Matura never runs your app and never phones home: everything is open source and stays
on your infrastructure.

> **Status: early development.** The control plane (`maturad`) has tenants, workspaces, members, apps, roles and
> data placements with row-level security; sign-in, invitations, the SDK and provisioning come next. Start with the
> [product definition](docs/plan/16-product-definition.md), the [delivery plan](docs/plan/20-end-to-end-delivery-plan.md),
> the [specifications](docs/spec/README.md) and the decisions in [`docs/adr/`](docs/adr/README.md). The first apps on
> Matura will be [DevFlow](https://github.com/marunsct/DevFlow) and [AgentCanvas](https://github.com/marunsct/AgentCanvas).

## Run it

```bash
make test        # starts a throwaway local Postgres and runs every test
make up          # Docker Compose: Postgres, Keycloak (realm "matura"), Mailpit and maturad on :8080
curl -X POST localhost:8080/v1/tenants -H 'X-Matura-Dev-User: 0192b7a4-5c1e-7d2a-9f00-4b1e2a9c0d11' \
     -H 'X-Matura-Dev-Email: ana@acme.test' -d '{"slug":"acme","name":"Acme"}'
```
> Contributors and agents: read [HANDOVER.md](HANDOVER.md) first.

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
| Agent identity: MCP authorisation, on-behalf-of tokens, agents as revocable tenant members, human-approval logs | Matura on Keycloak + OpenFGA |
| Readiness: SOC 2 / ISO 27001 / ISO 42001 / GDPR / EU AI Act control packs, readiness score in CI, continuous evidence exported to your GRC tool, policies, trust page | Matura |
| HA install of Matura itself on Compose or Kubernetes | Kubernetes, CloudNativePG, KEDA, Cilium (Apache-2.0) |
| SDKs for Python, TypeScript/React and Go; CLI; OpenTofu provider | Matura |

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Every bundled component must use an OSI-approved licence; see
[ADR 0002](docs/adr/0002-licence-policy.md).
