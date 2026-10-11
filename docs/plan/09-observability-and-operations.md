# 09 — Observability and operations

## 1. Telemetry

| Signal | Collection | Storage | Views |
|---|---|---|---|
| Metrics | OpenTelemetry SDKs and Prometheus exporters (Keycloak, CNPG, NATS, OpenFGA, Envoy have native ones) | Prometheus (short-term) + VictoriaMetrics cluster (long-term, multi-tenant by `tenant` label) | Perses dashboards as code; Grafana optional |
| Logs | structured JSON, OpenTelemetry Collector / Fluent Bit, PII scrubbing processor | OpenSearch with index lifecycle | OpenSearch Dashboards; tenant-filtered views in the tenant console for their app logs (opt-in) |
| Traces | OpenTelemetry SDKs, W3C trace context propagated from gateway → Keycloak → apps | Jaeger (OpenSearch backend) | Jaeger UI, linked from logs and audit (`trace_id`) |
| Audit | doc 07 §3 | Postgres (hash chain) + OpenSearch for search + WORM archive | consoles |
| Profiles | Pyroscope-compatible continuous profiling (optional, AGPL tool) or Go pprof on demand | | |

Every signal carries `tenant_id`, `app`, `region`, `cell`, `version` so incidents can be scoped per tenant.

## 2. SLOs and alerting

- SLOs defined as code (OpenSLO, Apache-2.0) and turned into multi-window burn-rate alerts (Sloth or Pyrra, both
  Apache-2.0): sign-in success and latency, token endpoint, control-plane API, SCIM, webhook delivery, backup
  freshness, restore test success.
- Alertmanager routes: paging for user-facing SLO burns and security alerts; tickets for capacity and certificate
  expiry; integrations with any on-call tool via webhooks (no vendor required).
- Golden dashboards per component and a per-tenant health view for support.

## 3. Operations

| Task | How |
|---|---|
| Install | `tenantry install` (wraps Helm/operator) with a guided config: domain, regions, identity providers, SMTP, object storage, KMS; Compose for evaluation |
| Upgrades | semantic versions; the operator upgrades components in order (databases → Keycloak → control plane → consoles) with pre-flight checks, automatic backups before upgrade, canary pods, rollback; Keycloak upgrades follow upstream migration notes and are tested in CI with production-like data |
| Configuration | GitOps via Argo CD; drift detection; all settings also available through the API |
| Certificates | cert-manager with expiry alerts at 30/7/1 days |
| Secrets rotation | scheduled rotation for DB credentials (dynamic), signing keys (Keycloak key rotation with overlap), SMTP and IdP secrets reminders |
| Status page | Gatus probes + public status page; incident notes written from the platform console; per-tenant notifications for incidents affecting their cell |
| Support bundle | `tenantry support bundle` collects versions, configs (redacted), recent logs and health for debugging |
| Runbooks | one per alert, in `docs/admin/runbooks/`, linked from alerts |
| Maintenance windows | per region; tenants notified; zero-downtime is the default so windows are rare |
| Cost management | per-tenant resource usage (OpenCost, Apache-2.0) feeds the platform console and billing |

## 4. Environments

- `dev` (Compose), `ci` (kind clusters with the full chart), `staging` (production-like, synthetic tenants, nightly
  DAST and load tests), `prod`. Promotion by Git tags through Argo CD; every release candidate soaks in staging for 48 h.
