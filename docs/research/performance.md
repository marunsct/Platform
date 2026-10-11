# Matura — Performance & Concurrency Design (research)

Status: research draft, 2026-10-11. Scope: maximum throughput / minimum tail latency for the
enterprise-readiness layer (Keycloak, Ory Polis, OpenFGA, OpenBao, `maturad`, SDKs, CNPG Postgres +
PgBouncer, Valkey, NATS JetStream, Temporal, SeaweedFS, OpenSearch, Envoy Gateway, OTel, VictoriaMetrics).

Legend: **[src]** = number taken from a cited source; **[est]** = engineering estimate to be validated by
our own benchmarks (see section 8). Many vendor numbers are best-case; we treat them as upper bounds.

Research note: web fetch of keycloak.org / openfga.dev was blocked from this sandbox (DNS); figures below
come from search-result extracts of those pages and are cross-checked against at least one other source
where possible. Re-verify exact numbers against the pages before publishing externally.

---

## 0. Core principle: three planes, one rule

| Plane | Components | Request-path role |
|---|---|---|
| **Data plane (in-app)** | SDKs (Go/TS/Python/React), optional Envoy ext_authz/JWT filter | Every app request. Must be local, allocation-light, never block on the network for authn. |
| **Decision plane** | OpenFGA (+ local cache), entitlement snapshot, rate-limit buckets | Per request where needed; bounded latency, cacheable, fail-mode defined. |
| **Control plane** | `maturad`, Keycloak admin, Polis, Temporal, OpenBao admin | Config / lifecycle / login. **Never** called synchronously on an app request. |

**Rule H0:** the app's hot path makes zero synchronous calls to `maturad` or Keycloak. Everything the
SDK needs (JWKS, tenant config, entitlement snapshot, feature flags, rate-limit policy) is *pushed* or
*pulled in background* and served from memory. Control-plane outage => app keeps serving with last-known
config (bounded staleness, explicit `max_stale`).

---

## 1. Hot path design

### 1.1 Authentication: local JWT verification

- **JWKS caching.** SDK fetches `/.well-known/jwks.json` (or a `maturad`-mirrored JWKS on CDN/edge) at
  startup, caches per `kid`, refreshes in background every 5–15 min with jitter, and on *unknown kid*
  does a single-flight refetch rate-limited to 1/30s (prevents kid-spray DoS). Keys are pre-parsed to
  `crypto.PublicKey` objects once; never per request.
- **Algorithm choice.** Verification cost in Go is tens of µs per token on commodity CPUs; published
  community benchmarks disagree on ordering (ES256 ~82–84 µs, EdDSA ~66–140 µs, RSA-1024 ~23 µs,
  RSA-2048 ~76 µs depending on CPU/Go version) **[src: github.com/cristaloleg gist,
  github.com/standardgalactic/jwt-1]**. RSA *verify* is cheap (small public exponent), ECDSA verify is
  costlier; signing is the reverse. Since tokens are signed once (Keycloak) and verified on every request
  across many services, **RS256 (2048) or EdDSA are both fine; benchmark on target hardware** and pick.
  Keycloak supports RS256/ES256/EdDSA realm keys.
- **Verified-token cache.** To get below the raw crypto cost, the SDK keeps an LRU keyed by
  `sha256(token)` -> parsed claims, TTL = `min(exp - now, 60s)`. A cache hit is a hash + map lookup
  (~1–2 µs) **[est]**. With typical token reuse (same browser session sends the same access token for
  minutes) hit ratios > 95% are expected **[est]**. Cache size bounded (e.g. 100k entries ≈ 50–100 MB
  worst case; tune per service).
- **Budget:** authn SDK overhead **p50 < 20 µs, p99 < 1 ms** (cache miss = 1 signature verify + JSON
  decode; p99 dominated by GC). Achievable in Go/TS/Python(with `cryptography` C backend).

### 1.2 Token claims: what goes into the access token

Claims carried (compact, namespaced): `sub`, `tid` (tenant), `wid` (active workspace), `org` (Keycloak
Organization id), `roles` (coarse, ≤ ~20), `ent_v` (entitlement snapshot version), `fga_rev`
(optional consistency token, see 1.4), `amr/acr`, `sid`.

- Keep tokens **< 2 KB** so they fit headers and keep verify/parse cheap. Large role sets explode token
  size — a documented failure mode where `resource_access` for many clients made the token too big for
  HTTP headers **[src: FOLIO EUREKA-704,
  https://folio-org.atlassian.net/wiki/spaces/FOLIJET/pages/887324704]**.
- Keycloak *lightweight access tokens* (24+) drop most claims by default, with per-mapper "Add to
  lightweight access token" opt-in **[src: https://www.keycloak.org/2024/03/keycloak-2400-released]**.
  We use lightweight tokens + an explicit mapper set (tenant/workspace/roles) via a Matura protocol
  mapper SPI. Do **not** rely on introspection to fill missing claims — that reintroduces a sync call.
- Fine-grained permissions stay **out** of the token (they go to OpenFGA); the token carries identity +
  tenancy + coarse role only.
- Workspace switch = token exchange / refresh with new `wid` (control-plane op, not hot path).

### 1.3 SDK-side caches (all in-process)

| Cache | Source | Refresh | Staleness bound |
|---|---|---|---|
| JWKS | Keycloak / maturad mirror | 5–15 min + unknown-kid | n/a (keys overlap during rotation) |
| Tenant config (tier, region, features, policies) | maturad snapshot via NATS KV watch or SSE | push | < 2 s typical |
| Entitlement snapshot | maturad/OpenMeter balance snapshot | push + 30 s poll | < 5 s |
| Authz decisions | OpenFGA | TTL 1–10 s, invalidated by revision | configurable |
| Rate-limit policy | maturad | push | < 2 s |

Distribution: NATS JetStream KV buckets (`tenant-config`, `entitlements`) with `watch` give push
semantics and replay on reconnect; SDKs that cannot hold a NATS connection (browser, serverless) poll a
CDN-cached ETag endpoint. Snapshots are versioned; SDK exposes `config_version` in OTel spans.

### 1.4 Authorization: OpenFGA latency, caching, consistency

Facts:
- OpenFGA caches: `check-query-cache` (off by default; limit 10,000 entries; TTL 10 s) used only for
  `MINIMIZE_LATENCY` consistency; `HIGHER_CONSISTENCY` bypasses it and "will have a significant impact
  in performance" **[src: https://openfga.dev/docs/interacting/consistency]**. An iterator cache
  (`check-iterator-cache`, TTL flag `OPENFGA_CHECK_ITERATOR_TTL`) caches datastore iterators
  **[src: https://openfga.dev/blog/fine-grained-news-2025-02]**.
- Server-side **BatchCheck** shipped in v1.8.0 with dedup in 1.8.1 **[src: openfga.dev fine-grained-news
  2024-11 / 2025-02]**. Note **CVE-2026-34972**: BatchCheck dedup cache-key collision with differing
  contexts, affects 1.8.0–1.13.1 — pin a fixed version **[src:
  https://www.wiz.io/vulnerability-database/cve/cve-2026-34972]**.
- OpenFGA reported `/check` "up to 10x faster in some scenarios" (2025) and a self-tuning planner
  **[src: https://openfga.dev/blog/fine-grained-news-2025-09]**.
- Known sharp edges: iterator-cache stampede re-reading the same tupleset up to 12x in one Check (PR
  #3309); `max-concurrent-reads` not bounding Postgres queries for ListObjects (issue #3326, v1.21);
  recursive fan-out holding hundreds of connections (issue #3094) **[src: github.com/openfga/openfga]**.
- Reference point for Zanzibar-style systems: Zanzibar reports p95 < 10 ms at Google scale; SpiceDB
  reached 1M QPS (1% writes, 100B relationships) at p95 5.76 ms on CheckPermission with >90% subproblem
  cache hit **[src: https://dev.to/authzed/google-scale-authorization-getting-to-1-million-qps-on-spicedb-dedicated-with-cockroachdb-22ha]**.
  This sets a realistic expectation: **remote** ReBAC checks are single-digit ms p95; sub-ms requires
  local caching.

Design:
1. **Model for shallow graphs.** Keep `tenant -> workspace -> resource` at depth ≤ 3; avoid `but not`
   and dual-direction recursion (documented latency blowups, issue #1338/#3094). Put tenant/workspace
   membership in token claims so many checks short-circuit in the SDK (`tid` mismatch => deny without
   calling FGA).
2. **Two-tier cache.** (a) SDK in-process decision cache keyed `(store, model_id, user, relation,
   object, ctx_hash)` TTL 1–5 s; (b) OpenFGA `check-query-cache` + iterator cache on, TTL 10 s.
   Negative results cached for shorter TTL (1 s) to limit "permission just granted but denied" UX.
3. **Consistency tokens ("zookie-lite").** OpenFGA has no per-request zookie like Zanzibar/SpiceDB
   ZedTokens; it offers `MINIMIZE_LATENCY` vs `HIGHER_CONSISTENCY`. We emulate read-your-writes:
   every tuple write through `maturad` returns a monotonically increasing `authz_rev` per tenant
   (stored in Valkey + broadcast on NATS `authz.rev.<tenant>`). SDK caches entries tagged with rev; if
   the request carries `X-Authz-Rev` (or the session saw a newer rev) greater than the cache's rev, the
   SDK bypasses its cache and calls FGA with `HIGHER_CONSISTENCY` for that tenant until the rev window
   (≈ cache TTL) passes. Result: strong-after-write for the writer, cheap reads for everyone else.
4. **Batch.** UI list pages use `BatchCheck` (≤ 50 per call) or `ListObjects` with a hard cap and
   pagination; never N sequential Checks. For list-heavy screens, prefer **pre-filtering in Postgres**
   by workspace (RLS) and FGA only for the page of ≤ 50 rows.
5. **Embedding vs sidecar vs central.**
   - *Central OpenFGA cluster* (default): HA, horizontally scaled, shared cache per replica; 1 network
     hop (~0.3–1 ms in-cluster) + eval.
   - *Sidecar / per-node DaemonSet*: OpenFGA is a stateless Go server over Postgres, so it can run
     per node with its own cache; saves the cross-node hop but multiplies DB connections (each replica
     needs a pool) — use only behind PgBouncer.
   - *Embedded (Go only)*: OpenFGA can be imported as a library (`pkg/server`), giving in-process
     Check; reserved for `maturad` itself and silo/self-hosted tiers.
   - Recommendation: central cluster + SDK cache; DaemonSet mode as an option for > 50k checks/s per
     cluster.
6. **Budget:** authz p50 < 0.1 ms (SDK cache hit), **p99 < 5 ms** (miss, in-region), BatchCheck(50)
   p99 < 15 ms **[est]**. Fail mode: configurable per route — `deny` (default) or `last-known-allow`
   for read-only routes during FGA outage, with alerting.
7. **OpenFGA DB sizing:** set `max-open-conns` to DB limit ÷ replicas, min idle ≈ 50–75% of that
   **[src: https://openfga.dev/docs/best-practices/running-in-production]**; dedicated CNPG cluster
   for FGA tuples (read-heavy, replicas for reads are not supported by FGA directly — scale the primary
   vertically first, partition by store if needed).

---

## 2. Keycloak at scale

### 2.1 Published numbers

| Workload | CPU cost | Source |
|---|---|---|
| Password logins | **1 vCPU per 15 logins/s** (tested to 300/s); older guide said 8/s per vCPU per pod | keycloak.org sizing guide (single- and multi-cluster) |
| Client-credentials grants | **1 vCPU per 120 grants/s** (tested to 2,000/s); older guide 450/s; cost dominated by TLS handshakes | same |
| Refresh-token requests | **1 vCPU per 120 refreshes/s** | https://www.keycloak.org/2025/10/keycloak-benchmark |
| Headroom | +150% CPU (older guide +200%); severe degradation when CPU-throttled | sizing guide |
| Memory | ~1,250 MB base per pod; heap = 70% of limit; ~300 MB non-heap | sizing guide |
| Cache limits | session / offline-session caches default 10,000 entries/node; > 2,500 concurrently-used clients overflow client caches -> DB bottleneck | https://www.keycloak.org/server/caching ; sizing guide |
| DB | example sizing lands on 2–4 vCPU Aurora; median latency +120 ms at 90% DB CPU | sizing guide |
| Persistent sessions | default in 26; p50 login/logout +20/+10 ms vs in-memory (25 preview, single-AZ DB) | https://www.keycloak.org/2024/06/persistent-user-sessions-in-preview |
| Benchmark harness | keycloak-benchmark (Gatling scenarios), 26.4 deep dive with 100k users | https://github.com/keycloak/keycloak-benchmark |

Sources: https://www.keycloak.org/high-availability/single-cluster/concepts-memory-and-cpu-sizing ,
https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing ,
https://www.keycloak.org/2025/10/keycloak-benchmark. A community user reports ~120 logins/s/vCPU after
lowering hash iterations **[src: https://forum.keycloak.org/t/10-000-logins-per-second/29347]**.

### 2.2 Password hashing is the login bottleneck

- Keycloak 25+ defaults to **Argon2id** (5 iterations, 7 MiB per hash, parallel hashes capped at JVM
  core count) for non-FIPS; FIPS uses PBKDF2-SHA512 at 210,000 iterations. KC 24 had raised PBKDF2 from
  27.5k to 210k (> 10x CPU) **[src: https://www.keycloak.org/docs/latest/release_notes/]**.
- Implication for **10k password logins/s**: 10,000 / 15 ≈ 667 vCPU + 150% headroom ≈ **1,670 vCPU**.
  That is the cost of *password* auth and it is not something to optimise by weakening hashes.
- Mitigations (in order):
  1. **Push enterprise users to SSO** (SAML/OIDC via Polis/Keycloak brokering) — no local hash.
  2. **Passkeys/WebAuthn** — signature verify, ~µs, no memory-hard KDF.
  3. **Long-lived SSO sessions** (e.g. 8–12 h idle, 30 d remember-me) so password entry is rare;
     most "logins" are SSO cookie re-auths costing about a refresh.
  4. Brute-force protection + Envoy rate limits on `/login-actions` to stop credential-stuffing from
     burning CPU (attackers pay nothing, we pay 7 MiB + CPU per attempt).
  5. Dedicated "login" Keycloak pod pool (HPA on CPU) separate from "token" pods serving refresh /
     client-credentials, via path-based routing in Envoy.

### 2.3 Keeping Keycloak off the critical path

- **Access token TTL 5–15 min, refresh in background** by SDK at ~75% of TTL with jitter (spreads
  refresh load; avoids thundering herd at the top of the minute). At 1M active sessions and 10-min
  tokens: ~1,667 refresh/s ≈ 14 vCPU (+headroom ≈ 35 vCPU) **[derived from 120/s/vCPU]**.
- **Service-to-service:** cache client-credentials tokens per (client, audience) until 80% of TTL;
  never fetch per request. Use HTTP keep-alive/HTTP2 to Keycloak (the 120/s figure is TLS-dominated).
- **Revocation without introspection:** short TTL + `sid`-based revocation list pushed via NATS
  (`authn.revoked`) to SDKs (bloom filter / set of revoked `sid`s with TTL = max token TTL).
- **Persistent sessions** (26 default) write to DB on login/refresh/logout — DB sizing matters; raise
  session cache `max-count` above concurrent active sessions per node to avoid DB reloads.
- **Realms/organizations:** use Keycloak Organizations inside a small number of realms (realm-per-tenant
  degrades with thousands of realms; see https://github.com/keycloak/keycloak/discussions/11074);
  silo tier gets its own realm/cluster.

### 2.4 Multi-site

- KC 26 multi-site: two sites, active-active, external Infinispan (Data Grid) cross-site, DB
  replicated synchronously; requires low-latency inter-site network; persistent sessions recommended;
  sessions-only-in-external-Infinispan is experimental **[src:
  https://www.keycloak.org/high-availability/concepts-multi-site ,
  https://www.keycloak.org/2024/12/storing-sessions-in-kc26]**. Community reports issues above ~30 ms
  RTT (unverified) — **design for metro distance (< 10 ms RTT)**; for true geo-distribution use
  independent regional clusters per tenant home region instead of stretching one.

---

## 3. Go control plane (`maturad`) concurrency

### 3.1 Process structure

- Stateless API replicas (HTTP/gRPC via connect-go) behind Envoy; background workers (outbox relay,
  projections, NATS consumers) in the same binary, toggled by flags, scaled separately.
- **Goroutine discipline:** one goroutine per request (net/http default) is fine; *never* unbounded
  fan-out — use `errgroup.SetLimit(n)` and per-dependency semaphores (`x/sync/semaphore`) sized to the
  downstream pool. All calls carry `context` deadlines derived from the request budget.
- Runtime: `GOMEMLIMIT` = 90% of container memory, `GOGC` 100–200, `GOMAXPROCS` matched to CPU quota
  (Go ≥ 1.25 is cgroup-aware); avoid CPU limits throttling (requests = limits for latency-critical).

### 3.2 Postgres pooling (pgx)

- `pgxpool` per replica sized from the **DB server** budget: Postgres optimum active connections ≈
  `(db_cores × 2) + spindles` **[src: PostgreSQL wiki formula as quoted,
  https://forum.elixirforum.com/t/ecto-pool-size/4120/5]**; total across replicas ≤ PgBouncer
  `default_pool_size`. Example: 16-core primary -> ~32–40 server connections behind PgBouncer; 20
  `maturad` replicas × `MaxConns=20` = 400 client conns multiplexed by PgBouncer.
- `MaxConnIdleTime` 5 min, `HealthCheckPeriod` 30 s, `MaxConnLifetime` 30–60 min with jitter.
- Acquire timeout = 50–100 ms; on timeout => 503 + `Retry-After` (backpressure, not queueing).

### 3.3 Backpressure, per-tenant rate limiting, fair queuing, load shedding

- **Two-layer rate limiting.**
  - *Local* token bucket (`golang.org/x/time/rate`) per (tenant, route-class) in each replica, with the
    tenant's quota divided by replica count (refreshed from membership). Zero network cost; slight
    over-admit tolerated (≤ N× burst).
  - *Global* GCRA in Valkey (Lua script, 1 RTT, ~0.2–0.5 ms in-cluster) only for strict quotas
    (billing-relevant API limits). Batch with local pre-check: deny locally first, consult Valkey only
    when local says allow. Valkey 8 handles ~1.19M RPS on a 16-core c7g.4xlarge **[src:
    https://valkey.io/blog/unlock-one-million-rps-part2/]** (independent tests on 8 vCPU did not reach
    1M) — one shard-per-~200k limit ops/s **[est]**, Valkey cluster mode for more.
  - At the edge, Envoy Gateway global rate limit (envoy ratelimit service backed by Valkey) for
    unauthenticated/abuse traffic.
- **Noisy-neighbour isolation.**
  - Per-tenant concurrency caps (in-flight semaphore keyed by tenant, e.g. max 5% of replica capacity
    for pool-tier tenants).
  - **Weighted fair queuing**: background work (exports, SCIM syncs, audit exports) goes through NATS
    subjects per tenant (`work.<tier>.<tenant>`) consumed round-robin with per-consumer `MaxAckPending`,
    so one tenant's 1M-user SCIM import cannot starve others. Temporal task queues per tier with
    worker rate limits (`TaskQueueActivitiesPerSecond`).
  - Tier-aware priority: silo/bridge tenants get dedicated worker pools.
- **Load shedding.**
  - Adaptive concurrency limit (Netflix concurrency-limits Gradient/Vegas style; Envoy has an
    adaptive_concurrency filter using minRTT gradient) **[src:
    https://netflixtechblog.medium.com/performance-under-load-3e6fa9a60581 ,
    https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter]**.
  - Priority classes: `critical` (token mint hooks, SCIM provisioning ACK, health) > `interactive`
    (console) > `batch`. Shed batch first; CoDel-style queue timeout (drop requests that waited longer
    than 50% of their deadline).
  - Respect client deadlines (`grpc-timeout`, `X-Request-Deadline`).
- **Idempotency keys.** All mutating APIs accept `Idempotency-Key`; stored in Postgres table
  `(tenant_id, key) PK, request_hash, response, status, expires_at` inserted in the same tx as the
  mutation (`INSERT ... ON CONFLICT DO NOTHING` then compare hash). Valkey front-cache for replay hits.
  TTL 24 h; partition by day for cheap expiry.
- **Transactional outbox -> NATS.** Mutation + `outbox` row in one tx; relay uses logical decoding
  (pgoutput/wal2json via a lightweight CDC like `pglogrepl`) or `SELECT ... FOR UPDATE SKIP LOCKED
  LIMIT 500` polling; publishes to JetStream with `Nats-Msg-Id = outbox.id` (JetStream dedup window)
  for exactly-once publish. Partition outbox relay by `hash(tenant_id) % N` to preserve per-tenant
  order and parallelize.
- **Horizontal scaling & leader election.** API is stateless (HPA on CPU + in-flight). Singletons
  (scheduler, outbox relay partition owners, key rotation) use Kubernetes `Lease`
  (`client-go/tools/leaderelection`) or Postgres advisory locks per partition; prefer **sharded
  ownership** (N partitions, each leased) over a single leader. Temporal handles long-running
  workflows (tenant provisioning, SCIM full syncs, key rotation). Temporal on Postgres is persistence-
  bound (~1k–4.5k state transitions/s reported with 512–2048 shards, unverified) **[src:
  https://markaicode.com/benchmarks/temporal-production-benchmark-latency/ ,
  https://dev.to/temporalio/scaling-temporal-the-basics-31l5]** — keep Temporal off per-request paths
  and give it its own CNPG cluster.

---

## 4. Postgres

### 4.1 RLS performance

- **Policy shape:** `USING (tenant_id = current_setting('app.tenant_id')::uuid)` — wrap in a scalar
  subselect or a `STABLE` function so it is evaluated once, not per row; built-in `=` on uuid is
  leakproof, so indexes are usable.
- **Leakproof pitfall:** non-LEAKPROOF functions/operators in policies or user predicates prevent the
  planner from pushing quals into index scans (seq scans despite indexes). Fix: keep policy predicates
  to built-in leakproof operators; don't mark complex functions LEAKPROOF casually (security risk)
  **[src: https://www.bytebase.com/blog/postgres-row-level-security-footguns/ ,
  https://www.cybertec-postgresql.com/en/when-is-a-function-leakproof/]**.
- **Membership lookups**: never a per-row subquery to a membership table under RLS; compute allowed
  workspace set once per tx (`SET LOCAL app.workspace_ids = '{...}'` from the verified token) and use
  `workspace_id = ANY(current_setting(...)::uuid[])` **[src:
  https://chat2db.ai/resources/blog/postgres-rls-performance-tuning]**.
- **Indexes lead with `tenant_id`** (then `workspace_id`, then the access key). Primary keys
  `(tenant_id, id)` with UUIDv7 ids (time-ordered, B-tree friendly). Unique constraints include
  `tenant_id`.
- **Test as the app role**, not owner/superuser (owners and BYPASSRLS skip policies — benchmarks lie).
  `FORCE ROW LEVEL SECURITY` on tables.

### 4.2 SET LOCAL with PgBouncer transaction mode

- Every request: `BEGIN; SELECT set_config('app.tenant_id', $1, true), set_config('app.workspace_ids',
  $2, true); ...; COMMIT;` — `set_config(..., true)` == `SET LOCAL`, scoped to tx, safe in
  transaction pooling; session `SET` is not **[src:
  https://stackharbor.com/en/knowledge-base/pgbouncer-transaction-pool-advanced/]**. Bundle the
  `set_config` into the first statement (pipelined with pgx batch) to save a round trip.
- **Prepared statements:** PgBouncer ≥ 1.21 supports protocol-level prepared statements in
  transaction mode via `max_prepared_statements` (e.g. 200); SQL-level `PREPARE` is not tracked
  **[src: https://www.crunchydata.com/blog/prepared-statements-in-transaction-mode-for-pgbouncer ,
  https://pganalyze.com/blog/5mins-postgres-pgbouncer-prepared-statements-transaction-mode]**.
  pgx default `QueryExecModeCacheStatement` works with this.
- Safety net: a pool-level `server_reset_query` is not run in tx mode, so a missing `SET LOCAL` would
  yield *no rows* (policy compares to NULL) — fail-closed by design; add a `CHECK`-style assertion
  function that raises if `app.tenant_id` unset.

### 4.3 Partitioning

- **Audit / events / idempotency / outbox:** range-partition by time (daily or weekly) with
  `pg_partman`; detach + archive to Parquet in SeaweedFS, drop partition (no VACUUM storms).
- **Tenant data (pool):** no per-tenant partitions (thousands of partitions hurt planning); hash
  partition by `tenant_id` (e.g. 16–64) only for the few very large tables, mainly for VACUUM
  parallelism. Large tenants graduate to **bridge** (schema/db) or **silo** tier.

### 4.4 CNPG scaling & connections

- CNPG `Pooler` CRDs: one `rw` pooler (primary) and one `ro` pooler (replicas) in transaction mode
  **[src: https://cloudnative-pg.io/documentation/1.25/connection_pooling]**. Read-only queries
  (console lists, reports) go to `ro` with tolerance for replica lag (expose `lag_ms`; route
  read-your-writes reads to primary for 2 s after a write via a session hint).
- Separate CNPG clusters per workload class: `core` (tenants/users/config), `fga` (tuples),
  `temporal`, `audit-hot`, `keycloak`. Prevents one class's I/O from hurting others.
- Postgres `max_connections` low (200–400); concurrency managed by PgBouncer.
- Synchronous replication (`synchronous_commit=remote_apply` or `on` with one sync standby,
  `ANY 1`) for core data; audit-hot can use `synchronous_commit=off` on ingest batches because the
  durable record already lives in JetStream (R3).
- **Citus** for very large pool tiers: row-based sharding on `tenant_id` with co-located tables gives
  single-node routing for tenant-scoped queries and the highest tenant density; schema-based sharding
  (Citus 12+) fits the bridge tier **[src:
  https://learn.microsoft.com/en-us/postgresql/citus/what-is-citus ,
  https://www.citusdata.com/blog/2016/12/22/scaling-out-sql-with-colocation/]**. Our `(tenant_id, …)`
  PK/FK convention keeps the migration path open. Citus is AGPL — ship as optional.

---

## 5. Audit log ingestion

### 5.1 Hash chain without global serialization

A single global chain caps throughput at one writer. Design:

1. **Per-tenant (or per tenant-shard) chains.** Each audit stream key = `tenant_id` (large tenants:
   `tenant_id/shard_k`, k = hash(actor) % 8). Order only within a chain. Throughput scales with tenants.
2. **Merkle batching.** The audit writer (consumer of JetStream subject `audit.<tenant>`) accumulates
   events for ≤ 200 ms or ≤ 1,000 events per chain, builds a Merkle tree (RFC 6962-style leaf/node
   domain separation), and appends one **batch record**: `{chain, seq, prev_batch_hash, merkle_root,
   count, t_first, t_last}`. Per-event cost = one SHA-256 (~1 µs) **[est]**; per-batch cost = one
   chain link + signature.
3. **Periodic anchoring.** Every 1 min, a global **checkpoint** = Merkle root over all chain heads,
   signed with an OpenBao transit key (Ed25519), written to object storage (WORM bucket / object lock)
   and optionally to an external transparency log / customer webhook. Signing cost is per minute, not
   per event.
4. **Proofs.** Inclusion proof = event -> batch root -> chain link -> checkpoint. Use the C2SP
   tlog-tiles format so verifiers can fetch static tiles; Trillian **Tessera** demonstrates > 10,000
   entries/s on POSIX and 5,000/s on GCP per log **[src:
   https://blog.transparency.dev/tessera-v1-0-is-here]** — per-tenant/batched leaves keep us far
   inside that even at 50k events/s globally (≈ 50–500 leaves/s after batching).

### 5.2 Ingestion pipeline

```
app SDK --(async, batched, gzip)--> maturad /audit (or NATS direct) --> JetStream AUDIT (R3, file)
   JetStream --> [chain-writer]  --> Postgres audit_hot (partitioned daily, COPY/batch insert)
             --> [search-sink]   --> OpenSearch (bulk 5–15 MB, refresh 30 s)  | or ClickHouse
             --> [archive-sink]  --> Parquet (zstd) on SeaweedFS hourly, per tenant/day prefix
```

- **SDK emit** is non-blocking: in-memory ring buffer (bounded, e.g. 10k events), flush every 100 ms
  or 500 events; on overflow -> spill to local disk (server SDKs) or drop + counter (browser, which
  should not be authoritative for audit anyway). Security-critical events (authn, admin actions) are
  emitted server-side by `maturad`/Keycloak event listener SPI, synchronously into JetStream
  (`PublishAsync` + ack await, ~ms).
- **JetStream numbers:** single-node file storage measured ~134k msgs/s (128 B, batch 500) in a
  community report; docs example batched ~627k msgs/s; sync publish ~35.7k msgs/s **[src:
  https://github.com/nats-io/nats-server/discussions/7599 ,
  https://docs.nats.io/using-nats/nats-tools/nats_cli/natsbench]**. R3 adds a Raft quorum ack per
  publish; publisher throughput drops sharply with many push consumers on one stream (discussion
  #6274). No authoritative R3 figure published -> **we must benchmark** (`nats bench --js --storage
  file --replicas 3`). Plan: split AUDIT into **N streams by subject partition** (`audit.p<0..15>.>`
  with deterministic subject-mapping partitioning by tenant) so each stream's Raft group lives on
  different leaders; async publish with window 256–1024; target 50k events/s (≈ 1 KB each ≈ 50 MB/s)
  across 16 streams ≈ 3k/s per stream — comfortable **[est]**.
- **Postgres hot store:** batch `COPY` 1k rows per call; partition daily; BRIN on `ts`, B-tree on
  `(tenant_id, ts DESC)`; 30–90 days hot, then Parquet only.
- **OpenSearch:** refresh_interval 30 s for audit indices (default 1 s), bulk sizing, replicas per
  durability needs; tuning yields ~60% more indexing throughput than defaults in OpenSearch's own test
  **[src: https://docs.opensearch.org/latest/tuning-your-cluster/performance/]**. Index per
  time (data streams / ISM rollover), routing by `tenant_id` to keep tenant queries on few shards;
  shard size 30–50 GB.

### 5.3 ClickHouse vs OpenSearch for audit

| Criterion | OpenSearch (Apache-2.0) | ClickHouse (Apache-2.0) |
|---|---|---|
| Full-text search on free-form fields | Native, strong | Token/ngram skip indexes, adequate for audit; full-text index newer |
| Aggregations / analytics over billions | Slower, heap-bound | Excellent (columnar, vectorized) |
| Storage | Inverted index overhead | Vendor reports > 50% less than OpenSearch; 12–19x compression on OTel logs vs Elasticsearch **[src: https://clickhouse.com/blog/elasticsearch-log-analytics-clickhouse]** (vendor benchmark) |
| Ingest | Bulk API; refresh/merge cost | 50B log rows loaded in < 4 h single node (vendor) |
| Ops | JVM, shard management | Fewer moving parts; Keeper for replication |
| Ecosystem fit | Dashboards, alerting, SIEM-like | Also used by OpenMeter -> one engine for audit analytics + metering |

Recommendation: **ClickHouse as the default audit analytics/search store** (shared with OpenMeter,
far cheaper per retained GB), OpenSearch as an optional plugin for customers needing rich full-text
/ SIEM features. Postgres keeps only the hash-chain metadata + 30-day hot window for API reads; the
authoritative archive is signed Parquet in object storage.

---

## 6. Metering & entitlement checks at high QPS

- OpenMeter: ingest API -> Kafka -> sink worker (dedup) -> ClickHouse; balance worker computes
  entitlement balances and publishes snapshots **[src: https://openmeter.io/docs/open-source/architecture]**.
  (We substitute or bridge Kafka with NATS/Redpanda as appropriate; OpenMeter expects Kafka.)
- **Entitlement check path:**
  - Boolean/feature entitlements and static limits: in the tenant config snapshot (SDK memory), O(1).
  - Metered limits (e.g. 10k API calls/month): SDK holds a **local lease** — maturad grants each SDK
    instance a slice of remaining quota (e.g. min(remaining/instances, 1% of limit)); SDK decrements
    locally (atomic counter) and requests a new lease when 80% consumed. Hard cutoff accuracy = lease
    size; soft limits allow overage then reconcile.
  - Balance snapshots from OpenMeter's balance worker update the lease grantor; SDK learns
    `ent_v` via NATS KV.
- **Usage emit:** local aggregation per (tenant, meter, window=10 s) — e.g. 100k events/s of
  "api_call" collapse to a few thousand aggregated CloudEvents/s; idempotent event IDs
  `(instance, window, meter)` for dedup.
- Budget: entitlement check p99 < 50 µs (memory) **[est]**; no network call on hot path.

---

## 7. Edge / gateway (Envoy Gateway)

- **Proxy overhead:** Istio (Envoy sidecars, 2 hops, mTLS, 1 kB, 1000 RPS) adds 0.18 ms p90 / 0.25 ms
  p99 (1.21), ~0.5 vCPU per 1000 RPS; earlier versions 1.3–2.7 ms **[src:
  https://istio.io/docs/ops/deployment/performance-and-scalability/]**. Per-core throughput claims
  range 20k–45k RPS (unverified blogs). Treat **≤ 0.5 ms p99 per hop** as the target.
- **Filter costs:** built-in C++ filters add ~5–8 µs; no-op WASM ~26 µs; no-op Lua ~81 µs (Lua 3x
  WASM latency, ~5x CPU) **[src: https://arxiv.org/pdf/2207.00592]**. => Use native filters (`jwt_authn`,
  `rbac`, `local_ratelimit`, `ext_authz`) and avoid Lua; WASM only for low-volume custom logic;
  consider Envoy dynamic modules (native shared objects) for hot custom logic.
- **JWT at the edge:** Envoy `jwt_authn` with remote JWKS caching validates tokens natively and can
  forward claims as headers (`x-tenant-id`), so apps behind the gateway can skip crypto (trust the
  mesh-authenticated header).
- **ext_authz:** adds a gRPC round trip per request; OPA's benchmark showed p90–p99 at least doubling
  vs Envoy alone with a no-op policy **[src: https://www.openpolicyagent.org/docs/envoy/performance]**.
  Use Envoy's native gRPC client (lower latency than Google gRPC client per OPA docs), run the
  ext_authz service (Matura authz adapter wrapping FGA + cache) as a **co-located** DaemonSet or
  same pod, enable `with_request_body` only when required, set `failure_mode_allow=false` and a tight
  `timeout` (e.g. 25 ms). Prefer SDK-level authz for fine-grained checks; ext_authz for coarse
  route-level policy.
- Edge rate limiting: `local_ratelimit` (per-Envoy, free) first; global ratelimit service for
  per-tenant API quotas. HTTP/2 + keep-alive to upstreams; circuit-breaker limits raised from defaults
  (defaults are low and queue requests).
- Adaptive concurrency filter in front of Keycloak and maturad for automatic load shedding.

---

## 8. Load testing & performance SLO program

### 8.1 Tooling

- **k6** (open source): one instance ≈ 30–40k VUs and up to ~300k RPS; use **k6-operator** for
  distributed runs (`parallelism`) beyond that **[src:
  https://grafana.com/docs/k6/latest/testing-guides/running-large-tests/]**. Thresholds
  (`http_req_duration{scenario:x}: ['p(99)<5']`) give non-zero exit codes -> CI gate.
- **keycloak-benchmark** (Gatling) for Keycloak flows, to compare with upstream numbers.
- `nats bench`, `pgbench` (custom RLS scripts), `ghz` for gRPC (OpenFGA, maturad), Nighthawk for
  Envoy, Go `testing.B` + `benchstat` for SDK micro-benchmarks.
- Results to VictoriaMetrics (k6 Prometheus remote-write output); traces sampled via OTel.

### 8.2 Scenarios (each as a k6 scenario with arrival-rate executor)

| # | Scenario | Target (reference cluster) |
|---|---|---|
| S1 | Password login (browser flow, Argon2 default) | 1k/s per 167 vCPU slice; scale-test 10k/s |
| S2 | SSO/passkey login + token refresh mix (80% refresh) | 10k/s combined |
| S3 | Client-credentials (cached + uncached) | 5k/s uncached |
| S4 | Authz Check via SDK (90% cache hit) / direct FGA | 100k/s SDK; 20k/s FGA uncached |
| S5 | BatchCheck(50) list pages | 2k/s |
| S6 | Audit emit | 50k events/s sustained, 150k/s burst 60 s |
| S7 | SCIM provisioning bulk (1M users one tenant) concurrently with S4 at other tenants | noisy-neighbour: others' p99 within +10% |
| S8 | maturad admin API mix (CRUD, idempotent retries) | 5k/s |
| S9 | Tenant onboarding (Temporal workflow) | 50/s |
| S10 | Soak: 24 h at 60% of peak | no memory growth, no p99 drift |
| S11 | Spike: 0 -> 3x peak in 10 s | shed with 429/503, recover < 60 s |

### 8.3 Continuous regression in CI

- **Per PR:** Go/TS/Python micro-benchmarks for SDK hot paths (JWT verify, cache hit, authz cache,
  entitlement check) with `benchstat` vs main; fail if > 10% regression with p < 0.05. Allocation
  budget assertions (`testing.AllocsPerRun`).
- **Nightly:** ephemeral kind/k3d or dedicated perf cluster (fixed instance types, no noisy
  neighbours), k6 S1–S8 at 25% scale for 15 min; thresholds tracked; trend dashboards; auto-bisect on
  regression.
- **Weekly / pre-release:** full-scale run + soak S10 + spike S11.
- Store results as JSON artifacts + VictoriaMetrics; compare release-to-release.

### 8.4 Chaos

- Chaos Mesh / Litmus experiments under load: kill Keycloak pod, kill OpenFGA, Postgres primary
  failover (CNPG switchover), NATS node loss (R3 should continue), Valkey loss (rate limiter falls
  back to local buckets), network latency +50 ms to control plane (hot path must be unaffected —
  this *verifies rule H0*), partition between sites.
- Pass criteria: hot-path SLOs hold during control-plane chaos; recovery times within RTO; no audit
  event loss (count reconciliation JetStream vs sinks vs chain).

---

## 9. Console frontend performance (brief)

- Next.js/React consoles: route-level code splitting; **JS budget ≤ 170 KB gz initial** per route,
  CI-enforced with `size-limit`/bundle analyzer; React Server Components + streaming SSR for data-heavy
  pages; skeletons via Suspense.
- Static assets immutable-hashed, CDN cache `max-age=31536000, immutable`; HTML not cached for
  authenticated pages; tenant branding (logo/CSS vars) served from CDN with short TTL + ETag.
- Core Web Vitals targets: LCP < 2.5 s, INP < 200 ms, CLS < 0.1 at p75; Lighthouse CI on PRs.
- Large tables: server-side pagination + virtualization (TanStack Virtual); audit search via
  cursor-based pagination against ClickHouse/OpenSearch, never offset.
- React SDK: auth state from memory, silent refresh in a worker/iframe-free flow (refresh token
  rotation with BFF cookie pattern), avoid re-render storms by memoizing permission hooks
  (`useCan()` backed by the shared SDK cache + BatchCheck coalescing within a 5 ms window).

---

## Performance architecture decisions

1. **No synchronous control-plane calls on the app hot path (H0).** All per-request inputs are local
   (JWT, pushed snapshots). Rationale: control-plane latency/outages become irrelevant to app SLOs;
   verified by chaos test (control plane +50 ms / down).
2. **Local JWT verification with pre-parsed JWKS and a verified-token LRU.** Rationale: raw verify is
   tens of µs; cache hits are ~µs; meets p99 < 1 ms without network.
3. **Lightweight, compact access tokens (< 2 KB) carrying tenant/workspace/coarse roles only.**
   Rationale: avoids header-size failures and per-request introspection; fine-grained perms go to FGA.
4. **SSO/passkeys first; long SSO sessions; background token refresh at 75% TTL with jitter.**
   Rationale: password logins cost ~1 vCPU per 15/s (Argon2); refresh costs ~1 vCPU per 120/s; making
   password entry rare is the single largest Keycloak cost lever.
5. **Separate Keycloak pools for login vs token endpoints, behind adaptive concurrency + rate limits.**
   Rationale: credential stuffing or login spikes must not starve refresh/client-credentials.
6. **Multi-site Keycloak only within metro latency; regional independent clusters for geo.**
   Rationale: synchronous DB replication + cross-site Infinispan are latency-sensitive.
7. **OpenFGA central cluster + SDK decision cache + server caches; tenant-rev "zookie-lite" for
   read-your-writes.** Rationale: remote ReBAC is single-digit ms at best (SpiceDB p95 5.76 ms at 1M QPS);
   sub-ms requires local cache; rev-tagging restores correctness after writes.
8. **Shallow authz models, token-claim short-circuits, BatchCheck/ListObjects with caps; pin FGA
   versions past CVE-2026-34972.** Rationale: graph depth and fan-out drive FGA latency and DB load.
9. **Two-layer rate limiting: local token buckets everywhere, Valkey GCRA only for strict quotas.**
   Rationale: removes a network hop from most requests while keeping billing-accurate limits.
10. **Per-tenant concurrency caps + weighted fair queues (NATS subjects / Temporal task queues per
    tier) + priority-based load shedding.** Rationale: noisy-neighbour isolation in the pool tier.
11. **Transactional outbox with JetStream message-ID dedup; sharded relay by tenant hash; sharded
    leases instead of a single leader.** Rationale: exactly-once publish, per-tenant ordering, no
    singleton bottleneck.
12. **RLS with SET LOCAL via set_config in the first pipelined statement; only leakproof built-in
    operators in policies; tenant-leading composite indexes; UUIDv7 keys.** Rationale: keeps RLS
    index-friendly and pooler-safe; fail-closed if context missing.
13. **PgBouncer (CNPG Pooler) transaction mode with protocol-level prepared statements
    (max_prepared_statements ≈ 200); small Postgres max_connections; per-workload CNPG clusters.**
    Rationale: Postgres throughput peaks near 2× cores active connections; isolation of I/O classes.
14. **Time partitioning for append-heavy tables; hash partitions only for the largest pool tables;
    graduate big tenants to bridge/silo; Citus as optional scale-out.** Rationale: cheap retention,
    bounded planning cost, clear scale path.
15. **Audit: per-tenant chains + Merkle batch records + minutely signed global checkpoints anchored
    to WORM object storage, tlog-tiles proofs.** Rationale: parallel ingestion with tamper evidence;
    signing cost amortized; verifiable without trusting the DB.
16. **Audit transport via partitioned JetStream streams (R3, file), async publish; fan-out sinks to
    Postgres hot window, ClickHouse (default) / OpenSearch (optional), and Parquet archive.**
    Rationale: decouples producers from sinks; ClickHouse shares infra with OpenMeter and is cheaper
    per GB.
17. **Entitlements from in-memory snapshots + local quota leases; usage pre-aggregated in SDK windows
    before OpenMeter.** Rationale: O(1) checks at any QPS; reduces metering ingest by orders of magnitude.
18. **Native Envoy filters only (jwt_authn, local/global ratelimit, adaptive concurrency); no Lua;
    WASM only off-hot-path; co-located ext_authz with tight timeout for coarse policy.** Rationale:
    native ~5–8 µs vs WASM ~26 µs vs Lua ~81 µs; ext_authz hop doubles tail latency if remote.
19. **Performance is a tested contract: SDK micro-benchmarks per PR, nightly k6 at 25% scale, weekly
    full-scale + soak + spike + chaos.** Rationale: regressions are caught before release; numbers in
    this doc marked [est] get replaced with measured values.
20. **Go runtime hygiene: GOMEMLIMIT, cgroup-aware GOMAXPROCS, requests = limits for latency-critical
    pods, bounded goroutine fan-out with deadlines.** Rationale: avoids CPU throttling (which Keycloak
    docs also flag as severely harmful) and GC-driven tail latency.

---

## SLO table

Reference deployment = "pool tier, one region, 3 AZ". Numbers are initial targets; [est] until measured.

| Path / component | Throughput target | Latency SLO | Availability | Notes |
|---|---|---|---|---|
| SDK authn (JWT verify, cached) | unbounded (in-process) | p50 < 20 µs, **p99 < 1 ms** | n/a (local) | cache miss = 1 signature verify |
| SDK authz (cache hit) | 100k checks/s per cluster aggregate | p50 < 0.1 ms, p99 < 0.5 ms | n/a | ≥ 90% hit ratio target |
| OpenFGA Check (miss, in-region) | 20k/s uncached per cluster | p95 < 3 ms, **p99 < 5 ms** | 99.95% | depth ≤ 3 models |
| OpenFGA BatchCheck(50) | 2k/s | p99 < 15 ms | 99.95% | |
| Entitlement check (SDK) | unbounded | p99 < 50 µs | n/a | lease-based |
| Password login (Keycloak) | 10k/s at scale (~1.7k vCPU incl. headroom) | p95 < 300 ms, p99 < 500 ms | 99.95% | Argon2 default |
| SSO/passkey login | 10k/s | p95 < 200 ms (excl. IdP) | 99.95% | |
| Token refresh | 20k/s (~170 vCPU + headroom) | p95 < 50 ms, p99 < 100 ms | 99.99% | background, jittered |
| Client-credentials (uncached) | 5k/s | p95 < 50 ms | 99.99% | SDK caches tokens |
| maturad admin API | 5k/s | p95 < 50 ms, p99 < 150 ms | 99.9% | control plane |
| SCIM provisioning (Polis -> maturad) | 2k ops/s | p95 < 200 ms ack | 99.9% | async apply |
| Rate-limit decision (local) | unbounded | p99 < 10 µs | n/a | |
| Rate-limit decision (Valkey GCRA) | 200k/s per shard | p99 < 2 ms | 99.95% | falls back to local |
| Audit emit (SDK -> durable JetStream) | **50k events/s sustained**, 150k/s burst | p99 < 25 ms to durable ack | 99.99% | 0 loss |
| Audit visible in search | — | p95 < 60 s end-to-end | 99.9% | refresh/batch bound |
| Audit checkpoint anchoring | 1/min | < 2 min lag | 99.9% | signed via OpenBao |
| Config/entitlement propagation | — | p95 < 2 s, p99 < 5 s | 99.9% | NATS KV push |
| Envoy gateway hop | 30k RPS per core [est] | p99 added < 0.5 ms | 99.99% | native filters |
| Tenant onboarding (Temporal) | 50/s | p95 < 30 s complete | 99.9% | |
| Console (web) | — | LCP < 2.5 s, INP < 200 ms p75 | 99.9% | |

### Primary sources

- Keycloak sizing: https://www.keycloak.org/high-availability/single-cluster/concepts-memory-and-cpu-sizing , https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing
- Keycloak 26.4 benchmark: https://www.keycloak.org/2025/10/keycloak-benchmark ; harness: https://github.com/keycloak/keycloak-benchmark ; ROSA results: https://www.keycloak.org/keycloak-benchmark/benchmark-guide/latest/report/rosa-benchmark-key-results
- Keycloak sessions/caching: https://www.keycloak.org/server/caching , https://www.keycloak.org/2024/06/persistent-user-sessions-in-preview , https://www.keycloak.org/2024/12/storing-sessions-in-kc26
- Keycloak hashing: https://www.keycloak.org/docs/latest/release_notes/ ; lightweight tokens: https://www.keycloak.org/2024/03/keycloak-2400-released ; multi-site: https://www.keycloak.org/high-availability/concepts-multi-site
- OpenFGA: https://openfga.dev/docs/interacting/consistency , https://openfga.dev/docs/best-practices/running-in-production , https://openfga.dev/blog/fine-grained-news-2024-11 , https://openfga.dev/blog/fine-grained-news-2025-09 , https://github.com/openfga/openfga/pull/3309 , https://github.com/openfga/openfga/issues/3326 , https://github.com/openfga/openfga/issues/3094 , https://www.wiz.io/vulnerability-database/cve/cve-2026-34972
- SpiceDB 1M QPS: https://dev.to/authzed/google-scale-authorization-getting-to-1-million-qps-on-spicedb-dedicated-with-cockroachdb-22ha
- RLS: https://www.bytebase.com/blog/postgres-row-level-security-footguns/ , https://www.cybertec-postgresql.com/en/when-is-a-function-leakproof/ , https://chat2db.ai/resources/blog/postgres-rls-performance-tuning
- PgBouncer prepared statements: https://www.crunchydata.com/blog/prepared-statements-in-transaction-mode-for-pgbouncer , https://pganalyze.com/blog/5mins-postgres-pgbouncer-prepared-statements-transaction-mode
- CNPG pooling: https://cloudnative-pg.io/documentation/1.25/connection_pooling ; Citus: https://learn.microsoft.com/en-us/postgresql/citus/what-is-citus
- NATS: https://docs.nats.io/using-nats/nats-tools/nats_cli/natsbench , https://github.com/nats-io/nats-server/discussions/7599 , https://github.com/nats-io/nats-server/discussions/6274
- Valkey: https://valkey.io/blog/unlock-one-million-rps-part2/
- Transparency logs: https://blog.transparency.dev/tessera-v1-0-is-here , https://transparency.dev/articles/tile-based-logs/
- ClickHouse vs ES/OpenSearch: https://clickhouse.com/blog/elasticsearch-log-analytics-clickhouse ; OpenSearch tuning: https://docs.opensearch.org/latest/tuning-your-cluster/performance/
- OpenMeter: https://openmeter.io/docs/open-source/architecture
- Envoy/Istio: https://istio.io/docs/ops/deployment/performance-and-scalability/ , https://arxiv.org/pdf/2207.00592 , https://www.openpolicyagent.org/docs/envoy/performance , https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter
- Load shedding: https://netflixtechblog.medium.com/performance-under-load-3e6fa9a60581
- Temporal: https://dev.to/temporalio/scaling-temporal-the-basics-31l5
- k6: https://grafana.com/docs/k6/latest/testing-guides/running-large-tests/
