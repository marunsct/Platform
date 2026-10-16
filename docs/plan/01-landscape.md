# 01 — Open-source landscape

Licences as reported in October 2026. Several projects changed licence in 2021–2025, so sprint P0 re-checks every
`LICENSE` file and records it in `deps/licences.yaml`, and CI fails on a disallowed licence (doc 12). Legend:
**Adopt** = required component, **Option** = supported alternative, **Avoid** = not open source or a poor fit.

## 1. Identity and authentication

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| Keycloak | Apache-2.0 | OIDC/OAuth 2.1, SAML 2.0, LDAP/AD, identity brokering (Google, GitHub, Microsoft, Apple, any OIDC/SAML), TOTP, WebAuthn/passkeys, required actions, brute-force detection, Organizations (25+, usable in 26.x), multi-site HA with external Infinispan; SCIM is experimental/preview and realm-scoped | **Adopt** (core) |
| Infinispan | Apache-2.0 | Keycloak's distributed cache; cross-site replication | **Adopt** (with Keycloak) |
| Keycloakify | MIT | build Keycloak themes in React | **Adopt** (themes) |
| Phase Two Keycloak extensions (keycloak-orgs etc.) | Elastic License v2 (since 2023) | organisations, per-org SCIM; ELv2 forbids offering as a managed service | **Avoid**; Matura writes Apache-2.0 equivalents |
| Zitadel | AGPL-3.0 (v3+) | first-class multi-tenancy, event-sourced | **Option** (plan B behind SDK) |
| Authentik | MIT + source-available enterprise directory | | Avoid for required features |
| Logto | MPL-2.0 | Organizations, good DX | Avoid (fit), reference for UX |
| Ory Kratos / Hydra / Keto / Oathkeeper | Apache-2.0 | headless; SAML/SCIM in Kratos are commercial | Avoid as core |
| **Ory Polis** (was BoxyHQ SAML Jackson) | Apache-2.0 | SAML-to-OIDC bridge and SCIM 2.0 directory sync, per tenant connection | **Adopt** (enterprise SSO self-service and SCIM) |
| Casdoor | Apache-2.0 | multi-org, Casbin | Avoid (maturity) |
| SuperTokens, Hanko | Apache-2.0 / AGPL parts | app-embedded auth | Avoid (scope) |

## 2. Authorisation

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| **OpenFGA** | Apache-2.0, CNCF incubating (2025) | Zanzibar-style relationship-based access control; stores per tenant; SDKs in many languages | **Adopt** (fine-grained permissions) |
| SpiceDB | Apache-2.0 | Zanzibar, strong consistency (zookies) | Option |
| Open Policy Agent | Apache-2.0, CNCF graduated | policy as code (Rego) | **Adopt** for platform policies (admission, API guard) |
| Cerbos | Apache-2.0 | stateless policy PDP | Option |
| Kyverno | Apache-2.0, CNCF | Kubernetes policies | **Adopt** (cluster policies) |

## 3. Data stores

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| **PostgreSQL** | PostgreSQL licence | row-level security, logical replication | **Adopt** |
| **CloudNativePG** | Apache-2.0 | Kubernetes operator: HA, failover, PITR backups via the Barman Cloud plugin (in-core object-store backup deprecated since 1.26) | **Adopt** |
| pgBackRest | MIT | backups outside Kubernetes | **Adopt** (Compose/VM installs) |
| PgBouncer | ISC | connection pooling (transaction mode works with `SET LOCAL`) | **Adopt** |
| Citus | AGPL-3.0 | sharding Postgres | Option for very large tenants, unmodified only |
| **Valkey** | BSD-3 | Redis-compatible cache (Redis itself moved off BSD in 2024) | **Adopt** |
| **NATS + JetStream** | Apache-2.0, CNCF | events, outbox fan-out, multi-region streams | **Adopt** |
| Apache Kafka | Apache-2.0 | very high-volume event streams | Option |
| **SeaweedFS** | Apache-2.0 | S3-compatible object storage, small to large | **Adopt** (default) |
| Ceph RGW (Rook) | LGPL-2.1 (Rook Apache-2.0) | enterprise-scale object storage | **Option** (large installs) |
| Garage | AGPL-3.0 | geo-distributed S3 | Option |
| MinIO community edition | AGPL-3.0, upstream archived / maintenance only (2025–26) | | **Avoid** |
| **OpenSearch** | Apache-2.0 | audit search, logs, security analytics | **Adopt** |

## 4. Secrets, keys and certificates

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| **OpenBao** | MPL-2.0, Linux Foundation | Vault fork from the last MPL release: transit encryption (envelope keys per tenant), PKI, dynamic DB credentials, namespaces per tenant | **Adopt** |
| HashiCorp Vault | BSL 1.1 (since 2023) | | **Avoid** |
| External Secrets Operator | Apache-2.0 | syncs secrets into Kubernetes | **Adopt** |
| cert-manager | Apache-2.0, CNCF | TLS certificates, ACME | **Adopt** |
| SOPS | MPL-2.0 | encrypted config in Git | **Adopt** (GitOps secrets) |

## 5. Platform, hosting and networking

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| **Kubernetes** (any conformant: k3s, RKE2, kubeadm, managed EKS/GKE/AKS) | Apache-2.0 | | **Adopt** |
| Talos Linux | MPL-2.0 | immutable Kubernetes OS for on-prem | Option |
| **Argo CD** | Apache-2.0, CNCF graduated | GitOps delivery of platform and apps | **Adopt** |
| Flux | Apache-2.0 | GitOps alternative | Option |
| **Cilium** | Apache-2.0, CNCF graduated | network policies per tenant, encryption in transit (WireGuard), Hubble flow logs | **Adopt** |
| **Envoy Gateway** | Apache-2.0 | Gateway API ingress, rate limiting, ext-authz | **Adopt** |
| Apache APISIX / Kong OSS | Apache-2.0 | API gateway alternatives | Option |
| **Coraza** | Apache-2.0 | WAF with OWASP Core Rule Set (as Envoy/proxy filter) | **Adopt** |
| **KEDA** | Apache-2.0, CNCF graduated | event-driven autoscaling | **Adopt** |
| Karpenter / Cluster Autoscaler | Apache-2.0 | node autoscaling | **Adopt** (per cloud) |
| **Capsule** | Apache-2.0 | namespace-based tenants with quotas and policies | **Adopt** (bridge tier) |
| **vCluster** | Apache-2.0 (platform product is commercial) | virtual cluster per tenant | **Adopt** (silo-lite tier) |
| Kamaji | Apache-2.0 | hosted control planes per tenant | Option (dedicated clusters) |
| Cluster API | Apache-2.0 | creates dedicated clusters | **Adopt** (silo tier) |
| Karmada | Apache-2.0, CNCF | multi-cluster scheduling | Option (multi-region) |
| Knative Serving | Apache-2.0, CNCF graduated | scale-to-zero app services | Option (app hosting) |
| KubeVela | Apache-2.0, CNCF | app delivery model (OAM) | Option; Matura's app manifest is simpler |
| Coolify | Apache-2.0 | single-server PaaS | Not a fit (no multi-tenant control plane), reference for UX |
| Dokploy | licence unclear | | Avoid |
| Backstage | Apache-2.0, CNCF | developer portal | Option (developer portal plug-in) |
| Crossplane | Apache-2.0, CNCF | cloud resources as Kubernetes objects | Option (managed services per tenant) |
| OpenTofu | MPL-2.0, Linux Foundation | infrastructure as code (Terraform went BSL) | **Adopt** |
| **Velero** | Apache-2.0 | cluster and volume backups | **Adopt** |

## 6. Observability

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| **OpenTelemetry** (SDKs, Collector) | Apache-2.0, CNCF | traces, metrics, logs | **Adopt** |
| **Prometheus** + Alertmanager | Apache-2.0, CNCF graduated | metrics and alerts | **Adopt** |
| **VictoriaMetrics** (single and cluster) | Apache-2.0 | long-term multi-tenant metrics | **Adopt** |
| **Perses** | Apache-2.0, CNCF | dashboards as code | **Adopt** (default dashboards) |
| Grafana, Loki, Tempo, Mimir | AGPL-3.0 | popular; fine unmodified | **Option** |
| **Jaeger** | Apache-2.0, CNCF graduated | traces | **Adopt** |
| OpenSearch + Dashboards | Apache-2.0 | logs and audit search | **Adopt** |
| Fluent Bit | Apache-2.0 | log shipping | **Adopt** |
| Wazuh | GPL-2.0 | SIEM / host intrusion detection | Option (customer SIEM) |
| Falco | Apache-2.0, CNCF graduated | runtime threat detection | **Adopt** |
| Uptime Kuma / Gatus | MIT / Apache-2.0 | status page and probes | **Adopt** (Gatus) |

## 7. Billing, flags, email, workflows

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| **OpenMeter** | Apache-2.0 (acquired by Kong 2025; open-source future promised, watch) | usage metering, entitlements | **Adopt** (metering) |
| **Kill Bill** | Apache-2.0 | subscriptions, invoices, payment plug-ins | **Adopt** (billing, optional module) |
| Lago | AGPL-3.0, some premium features | | Option |
| **OpenFeature** + flagd | Apache-2.0, CNCF | feature flags | **Adopt** |
| Unleash / Flagsmith | Apache-2.0 / BSD | flag servers with UI | Option |
| **Temporal** | MIT | durable workflows (onboarding, offboarding, tenant provisioning) | **Adopt** |
| Postal | MIT | self-hosted mail server | Option; default is any SMTP relay |
| Mailpit | MIT | catches mail in development | **Adopt** (dev) |

## 8. Supply chain and security tooling

| Project | Licence | Notes | Verdict |
|---|---|---|---|
| Sigstore cosign | Apache-2.0 | sign images and charts | **Adopt** |
| Syft / Grype | Apache-2.0 | SBOM and vulnerability scan | **Adopt** |
| Trivy | Apache-2.0 | image, IaC and secret scanning | **Adopt** |
| OSV-Scanner | Apache-2.0 | dependency vulnerabilities | **Adopt** |
| Semgrep CE / gosec / CodeQL queries | LGPL / Apache / MIT | static analysis | **Adopt** (CI) |
| OWASP ZAP | Apache-2.0 | dynamic scanning | **Adopt** (nightly) |
| SLSA generators | Apache-2.0 | build provenance | **Adopt** |
| OpenSSF Scorecard | Apache-2.0 | project health | **Adopt** |

## 9. Sources consulted (October 2026)

- Identity comparisons: [SuperTokens](https://supertokens.com/blog/sso-providers),
  [Skycloak 2026 comparison](https://skycloak.io/blog/open-source-authentication-comparison-2026/),
  [Keycloak vs Zitadel](https://skycloak.io/blog/keycloak-vs-zitadel-comparison/),
  [Logto vs Ory vs Keycloak](https://www.pkgpulse.com/guides/logto-vs-ory-vs-keycloak-open-source-identity-providers-2026)
- Zitadel licence: [Moving to AGPL 3.0](https://zitadel.com/blog/apache-to-agpl), [licence FAQ](https://zitadel.com/license-faq)
- Keycloak: [multi-site concepts](https://www.keycloak.org/high-availability/concepts-multi-site),
  [Organizations multitenancy](https://skycloak.io/blog/multitenancy-in-keycloak-using-the-organizations-feature/),
  [SCIM status](https://phasetwo.io/blog/orgs-scim-experimental/), [CNPG recovery guide](https://www.keycloak.org/high-availability/single-cluster/deploy-cnpg-recovery)
- Phase Two licence: [licensing change](https://phasetwo.io/blog/licensing-change/)
- Ory Polis: [Ory acquires BoxyHQ](https://www.ory.com/blog/introducing-ory-polis-for-enterprise-single-sign-on), [repository](https://github.com/ory/polis)
- Authentik licence: [discussion #18682](https://github.com/goauthentik/authentik/discussions/18682)
- OpenFGA: [CNCF incubating](https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/)
- MinIO status: [InfoQ](https://infoq.com/news/2025/12/minio-s3-api-alternatives/)
- CloudNativePG backups: [Barman Cloud plugin](https://cloudnative-pg.io/plugin-barman-cloud/docs/intro/)
- OpenBao: [OpenBao vs Vault](https://wz-it.com/en/blog/openbao-vs-vault-comparison/)
- vCluster: [CNCF multitenancy news](https://www.infoq.com/news/2025/10/cncf-vcluster-multitenancy)
- Grafana licences: [relicensing to AGPLv3](https://grafana.com/blog/2021/04/20/grafana-loki-tempo-relicensing-to-agplv3)
- Billing: [Kill Bill](https://killbill.io/), [Kong acquires OpenMeter](https://konghq.com/blog/news/kong-acquires-openmeter)
- PaaS: [Coolify vs Dokploy](https://openalternative.co/compare/coolify/vs/dokploy)
