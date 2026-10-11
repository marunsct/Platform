# 08 — Scale, availability, backup and disaster recovery

## 1. Targets (defaults for the "Standard" and "Hyperscale" shapes; operators can change them)

| Measure | Target |
|---|---|
| Availability, sign-in and token endpoints | 99.95% monthly (Standard), 99.99% (Hyperscale multi-region) |
| Availability, consoles and control-plane API | 99.9% / 99.95% |
| Token issuance latency | p99 < 300 ms at 2,000 sign-ins/s per region |
| Grants/check latency via SDK | p99 < 10 ms (cached), < 50 ms (OpenFGA check) |
| RPO (data loss on disaster) | ≤ 5 minutes in region (WAL streaming); ≤ 15 minutes cross-region |
| RTO (time to restore service) | ≤ 15 minutes for zone loss (automatic), ≤ 1 hour for region loss (Standard: restore; Hyperscale: failover) |
| Scale | 10M+ users, 1M+ tenants, 100k+ concurrent sessions per region |

## 2. Scaling each component

| Component | How it scales |
|---|---|
| Envoy Gateway | horizontal; HPA on CPU and connections; regional anycast or DNS load balancing in front |
| Keycloak | stateless pods with distributed Infinispan caches; sessions in external Infinispan (persistent sessions) so pods can scale freely; HPA on CPU and request rate; separate node pool; database connection pooling; realm and client caches warmed; benchmarks with the Keycloak benchmark suite (k6/Gatling) every release |
| `tenantryd` | stateless; HPA/KEDA on RPS and latency; read replicas for list endpoints; grants cached in Valkey with event invalidation |
| Workers (Temporal) | KEDA on task-queue backlog; per-tier task queues for fairness |
| OpenFGA | stateless servers on Postgres, horizontal; check cache; per-tenant stores keep models small |
| Postgres (control, Keycloak) | CNPG cluster (1 primary + 2 sync/async replicas across zones), PgBouncer; vertical scaling first, then read replicas; partition large tables (audit, usage) by time; sharding with Citus or tenant-to-cluster mapping when one primary is not enough |
| App databases | pool tier: shard tenants across many CNPG clusters through the tenant directory (cell architecture); silo: own cluster |
| Valkey | Valkey Cluster or Sentinel; caches only, so loss is tolerable |
| NATS JetStream | 3- or 5-node clusters per region; super-cluster with gateways across regions; stream replication factor 3 |
| OpenSearch | data/ingest/master node roles, index lifecycle management (hot-warm-cold), snapshot to object storage |
| Object storage | SeaweedFS with volume replication, or Ceph RGW for petabyte scale; cross-region bucket replication for DR |
| Kubernetes | Cluster Autoscaler or Karpenter; multiple node pools; PodDisruptionBudgets; topology spread across zones |

**Cell architecture for hyperscale:** a *cell* is a full stack (app plane + databases) serving a set of tenants in one
region. The global tenant directory routes each tenant to its cell. New cells are added as tenants grow; a bad
deploy or failure affects only one cell; large tenants get their own cell (silo). Keycloak and the control plane
run per region; the directory and platform admin are global (replicated).

## 3. High availability within a region

- Three availability zones; every stateful service runs replicas across zones with anti-affinity.
- CNPG automatic failover (seconds); synchronous replication for the control and Keycloak databases (no data loss
  on primary failure).
- Keycloak load-balancer health checks (`/lb-check`), graceful shutdown, session persistence in Infinispan.
- PodDisruptionBudgets so upgrades and node drains never drop below quorum.
- Readiness gates on dependencies; circuit breakers and timeouts in SDKs (fail closed for authorisation, cached
  tokens still verify offline with JWKS).

## 4. Multi-region

| Mode | How | Trade-off |
|---|---|---|
| **Active-passive** (1.0) | primary region serves; standby region receives CNPG replica clusters (WAL shipping via object storage or streaming), Infinispan cross-site for Keycloak, NATS mirrors, object-storage replication; failover runbook + `tenantry dr failover` promotes the standby and flips DNS | simple, RPO minutes, RTO < 1 h |
| **Active-active by tenant** (1.x) | each tenant has a home region (residency) and is served there; each region is primary for its tenants and standby for another region's; global directory replicated | no cross-region write conflicts; a region loss affects only its tenants until failover |
| **Keycloak multi-site** | Keycloak's documented multi-site setup: two sites, synchronously replicated database, external Infinispan with cross-site replication, load balancer health-based routing | needs low-latency link between sites; manual resync steps after link failure (documented upstream) |

## 5. Backups

| Data | Method | Frequency / retention (default) |
|---|---|---|
| Postgres (all clusters) | CNPG + Barman Cloud plugin: continuous WAL archiving + base backups to object storage (encrypted, object-lock) | base daily, WAL continuous; PITR window 14 days; monthly backups kept 12 months; yearly 7 years (configurable) |
| Postgres (Compose/VM installs) | pgBackRest to object storage | same |
| Per-tenant logical exports | `pg_dump` filtered by tenant (pool) or full DB (silo), encrypted with tenant key | weekly + on demand; used for tenant restore and portability |
| Kubernetes resources and volumes | Velero (with CSI snapshots or Kopia file backups) | daily, 30 days |
| OpenBao | integrated storage (Raft) snapshots, encrypted | hourly, 30 days; unseal/recovery keys escrowed separately |
| Keycloak | its database (above) + realm export as code in Git | continuous + every change |
| NATS JetStream | stream snapshots / mirrors to the DR region | continuous |
| OpenSearch | snapshot repository on object storage | daily |
| Object storage | versioning + cross-region replication + object lock for audit and backups | continuous |
| Configuration | everything as code in Git (Argo CD), SOPS-encrypted values | every change |

Backups are encrypted, immutable for their retention (object lock, governance or compliance mode), stored in a
different account/project and region from production, and monitored (alert if a backup is late or a WAL gap appears).

## 6. Restore and drills

- **Point-in-time restore** of a whole cluster (CNPG bootstraps a new cluster from backup + WAL to a timestamp).
- **Single-tenant restore** without affecting others: restore into a scratch cluster at the requested time, extract
  that tenant's rows by `tenant_id`, verify, and merge back through a workflow (or swap the tenant's silo database).
- **Automated restore tests:** weekly job restores the latest backup of every cluster into an isolated namespace,
  runs integrity checks (row counts, checksums, app smoke tests) and records the result as compliance evidence;
  alert on failure.
- **DR game days:** quarterly region failover exercise in staging, yearly in production for Hyperscale installs;
  chaos experiments (Chaos Mesh or LitmusChaos, both Apache-2.0) for pod, node, zone and network faults.

## 7. Capacity and performance engineering

- Load tests (k6, AGPL used as a tool; or Gatling, Apache-2.0) for sign-in, token refresh, SCIM bursts, grant checks,
  console lists, with published baselines per release; regressions over 10% block the release.
- Capacity model per component (users, RPS, storage growth) in the platform console with forecasts.
- Rate limits and quotas protect shared cells; tenants exceeding fair use get moved to their own cell.
