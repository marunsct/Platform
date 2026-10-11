# 14 — Risks and open decisions

## 1. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scope: this is a large platform | high | high | phased roadmap; 1.0 scope fixed (doc 00 §5); AgentCanvas as the forcing first customer; everything else after 1.0 |
| Keycloak gaps (per-org roles, SCIM, admin UX) take longer than planned | medium | medium | roles and SCIM live in Tenantry (not Keycloak); Ory Polis for SAML/SCIM; Zitadel adapter as plan B behind the SDK |
| Keycloak upgrade breaks extensions | medium | medium | extensions only use public SPIs; upgrade CI against the next Keycloak release candidates |
| Upstream licence changes (as happened to Vault, Terraform, Redis, MinIO, Phase Two) | medium | high | licence gate in CI, quarterly audit, pluggable interfaces for metering, cache, object storage, secrets; prefer foundation-governed projects (CNCF, Linux Foundation) |
| Security bug in our own code (identity is a high-value target) | medium | very high | no custom crypto or password code; two-person review on identity paths; fuzzing; pen tests; bug bounty; fast security releases |
| Operating complexity for small adopters | high | medium | Compose and single-cluster shapes, sane defaults, `tenantry install` wizard, managed-hosting option later |
| RLS performance on large tables | low | medium | indexes leading with workspace id, partitioning, benchmarks in TS20 |
| Email deliverability for onboarding | medium | medium | SMTP relay of choice, domain authentication checks, bounce handling |
| OpenMeter direction after Kong acquisition | medium | low | metering is pluggable; built-in aggregator fallback |
| Community adoption | medium | medium | great docs, quick-starts, honest comparisons, AgentCanvas as a showcase |

## 2. Decisions for the owner

| # | Decision | Recommended |
|---|---|---|
| 1 | Approve the approach: adopt Keycloak (unforked) + Ory Polis + OpenFGA + OpenBao and the cloud-native stack, build the control plane, consoles, SDKs and operator | yes |
| 2 | Project name (working name "Tenantry"; the repository is `marunsct/Platform`) | keep "Tenantry" as the product name, or pick another |
| 3 | Licence for our code: Apache-2.0 | Apache-2.0 |
| 4 | Control-plane language: Go | Go (Python SDK stays first-class) |
| 5 | Order versus AgentCanvas sprints: run Tenantry in parallel threads, with AgentCanvas's database-isolation work (its T5) early | parallel |
| 6 | Onboarding default: set-password link, with generated temporary password as an option | link default |
