# 04 — Multi-tenancy and isolation

## 1. Tenant model

| Concept | Meaning |
|---|---|
| **Installation** | one Tenantry deployment, run by a platform operator (you, or anyone hosting it) |
| **Tenant** | a customer account. Kinds: `company` (an organisation), `shared` (one per installation, holds individual users), `personal` (optional, if an operator prefers GitHub-style personal accounts) |
| **Workspace** | where an app keeps data; the isolation unit for data. A company has one or more; each individual in the shared tenant gets a private personal workspace |
| **App instance** | an app's deployment serving one or many tenants |

A user can belong to many tenants; the account portal and every app's switcher move between them. Upgrading an
individual to a company moves their personal workspace into a new tenant (data stays, ownership changes).

## 2. Isolation tiers (per tenant, changeable later by migration)

| Tier | Data | Compute | Network | Keys | For |
|---|---|---|---|---|---|
| **Pool** (default) | shared database and schema, `tenant_id`/`workspace_id` on every row, Postgres RLS forced | shared app pods; per-tenant quotas and rate limits | shared, policies per app | per-tenant data key in OpenBao | individuals, small teams |
| **Bridge** | dedicated schema or database on a shared Postgres cluster | dedicated namespace (Capsule) or vCluster, own quotas | Cilium policies isolating the namespace | per-tenant key, optional BYOK | mid-market |
| **Silo** | dedicated Postgres cluster (CNPG) and object-storage bucket | dedicated node pool or dedicated cluster (Cluster API / Kamaji) | dedicated gateway, private link / VPN, IP allow-lists | BYOK / HYOK via customer KMS or HSM | enterprise, regulated |
| **Self-hosted** | customer runs its own installation (air-gapped bundle) | theirs | theirs | theirs | sovereign, defence |

Apps declare which tiers they support in their manifest; the operator provisions accordingly. Moving a tenant
between tiers is a Temporal workflow: snapshot, copy, verify checksums, switch routing in the tenant directory,
keep the old copy read-only for 7 days.

## 3. Database isolation (pool tier)

- Every tenant-owned table: `tenant_id` and `workspace_id` `NOT NULL`, composite foreign keys
  `(workspace_id, parent_id) → parent(workspace_id, id)` so a child can never point into another workspace.
- `ALTER TABLE … ENABLE ROW LEVEL SECURITY; ALTER TABLE … FORCE ROW LEVEL SECURITY;` with policy
  `USING (workspace_id = current_setting('tenantry.workspace_id', true)::text)` (and a tenant-level variant for
  tenant-wide tables). No context set → no rows.
- Apps connect as a role that owns nothing and has no `BYPASSRLS`; migrations run as the owner role; a separate
  audited `maintenance` role is the only bypass.
- The SDK sets `SET LOCAL tenantry.tenant_id / workspace_id / user_id` at the start of each transaction; works with
  PgBouncer transaction pooling. Background jobs set it from the job's row. Public credentials (share links, webhooks,
  API keys) resolve the workspace first.
- SDK helpers: Alembic/Goose/Prisma migration helpers that add the columns, backfill, FKs and policies; a linter in
  CI that fails if a new table lacks RLS.
- Indexes lead with `workspace_id`; partitioning by `tenant_id` hash for very large tables; Citus for sharding
  across nodes when a single cluster is not enough (doc 08).
- Tests: a generated cross-tenant suite calls every API route as tenant B with tenant A's ids, with the app's own
  checks disabled, and must get 404/empty.

## 4. Other data paths

| Store | Isolation |
|---|---|
| Object storage | bucket per tenant (silo) or prefix per tenant with per-prefix IAM policies; server-side encryption with the tenant's key; presigned URLs scoped and short-lived |
| Cache (Valkey) | key prefix `t:<tenant>:`; ACL users per app; no shared mutable keys across tenants |
| Search (OpenSearch) | index per tenant for large tenants, or document-level security filtered by tenant |
| Events (NATS) | subjects `tenantry.<tenant>.>`; accounts per app; JetStream streams with subject filters; tenants can only subscribe to their own subjects |
| Vectors / AI data | always filtered by workspace in the query; per-tenant collections for silo |
| Logs and traces | `tenant_id` attribute; tenant-facing views filtered; PII scrubbing in the OpenTelemetry Collector |
| Backups | encrypted per tenant key in silo tier, so a tenant's backup can be shredded independently |

## 5. Compute and network isolation

- Namespaces per app (pool) or per tenant (bridge) managed by **Capsule**: ResourceQuota, LimitRange, allowed
  registries, Pod Security "restricted", no host access.
- **vCluster** per tenant when a tenant needs its own Kubernetes API (custom operators, admin access).
- **Cilium** network policies: default deny, allow only declared app-to-app and egress destinations; WireGuard
  encryption between nodes; egress gateway with fixed IPs per tenant on request.
- Untrusted code (user scripts, AI agent tools) runs in **gVisor** (Apache-2.0) or **Kata Containers** (Apache-2.0)
  sandboxes with no service-account token and egress allow-lists.
- Noisy neighbours: per-tenant rate limits at the gateway (Envoy global rate limit with Valkey), per-tenant
  concurrency limits in the SDK, fair-share queues (Temporal task queues per tier), priority classes.

## 6. Keys and encryption per tenant

- OpenBao **transit** key per tenant (envelope encryption): apps call the SDK to encrypt/decrypt fields; data keys
  cached briefly in memory; rotation yearly or on demand, re-wrap without downtime.
- **BYOK**: tenant supplies a key from their AWS KMS, GCP KMS, Azure Key Vault or HSM (PKCS#11); OpenBao uses it as
  the wrapping key; revoking it makes the tenant's data unreadable (HYOK for silo).
- **Crypto-shredding** on tenant deletion: delete the tenant's key after the grace period; backups become unreadable.
- Secrets per tenant (API tokens of their integrations) in OpenBao namespaces, never in app databases in clear.

## 7. Data residency

- Each tenant has a **home region**; its data, backups and logs stay there. A small **global tenant directory**
  (tenant id → region, domains, routing) replicated to every region contains no personal data beyond tenant names
  and verified domains.
- Users signing in are routed to their tenant's region (domain or tenant slug in the URL, or a region picker for
  the shared tenant).
- Region moves are a workflow with tenant-owner approval.
- Sub-processor list and data-flow diagram generated from the installation's configuration.

## 8. Tenant lifecycle

| State | What happens |
|---|---|
| Provisioning | workflow creates Keycloak organization, OpenFGA store, OpenBao key, workspace rows, DB/namespace for bridge/silo, default roles, owner invitation |
| Active | normal |
| Suspended | sign-in blocked except owners (read-only, billing), API keys disabled, apps notified |
| Deleting (grace 7–30 days, configurable) | owners can restore; exports available |
| Deleted | rows purged, keys destroyed, object storage deleted, certificate of deletion generated and stored in the audit log |
