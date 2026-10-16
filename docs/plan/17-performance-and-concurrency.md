# 17 — Performance and concurrency

*2026-10-11 · distilled from [research/performance.md](../research/performance.md), which has the numbers, sources and
reasoning. Where docs 02 and 08 disagree with this document, this one wins. Figures marked [est] are targets to be
replaced by measured values in sprint TS21 (doc 13).*

## 1. The one rule

**Your app never waits on Matura.** Every per-request decision the SDK makes (who is this, which tenant, may they do
this, are they within their plan, are they rate-limited) is answered from memory inside the app process. Keys,
tenant settings, entitlements and limits are pushed to the SDK ahead of time (NATS KV, or an ETag-polled HTTP feed
when NATS is not reachable) and cached. If every Matura service goes down, apps keep serving signed-in users until
their tokens expire; nightly chaos tests prove this by adding 50 ms latency to, then stopping, the control plane.

Three planes follow from it:

| Plane | What runs there | Latency class |
|---|---|---|
| Data plane (in the app) | SDK: token checks, permission cache, entitlement and rate-limit checks, audit emit | microseconds |
| Event plane | NATS JetStream, outbox relays, audit and usage pipelines | milliseconds, asynchronous |
| Control plane | `maturad`, Keycloak, OpenFGA, Temporal, consoles | tens of milliseconds, never on the app's request path |

## 2. Decisions

1. **Tokens checked locally.** JWKS keys are parsed once and verified tokens are cached; one verify costs tens of
   microseconds, a cache hit about one. Access tokens stay under 2 KB and carry only tenant, workspace and coarse
   roles (Keycloak lightweight tokens); fine-grained permissions go to OpenFGA.
2. **Keycloak kept off the critical path.** Password logins are the expensive operation (about 1 vCPU per 15 logins/s
   with Argon2, against 1 vCPU per 120 refreshes/s). So: SSO and passkeys first, long SSO sessions, background token
   refresh at 75% of lifetime with jitter, separate Keycloak pools for login pages and token endpoints so a
   credential-stuffing burst cannot starve refreshes, Infinispan caches sized above defaults. Multi-site Keycloak only
   within one metro area; other regions run independent clusters.
3. **Permissions cached in the SDK.** OpenFGA runs as a central cluster with its query and iterator caches on; the SDK
   keeps a decision cache (target 90%+ hit rate) and uses BatchCheck for lists. OpenFGA has no consistency tokens, so
   Matura keeps a per-tenant revision number: the SDK drops cached decisions and asks with higher consistency right
   after a permission change. Authorisation models stay shallow (depth 3 or less), and checks short-circuit on token
   roles where they can. Pin OpenFGA to a version past CVE-2026-34972.
4. **Entitlements and limits are local.** Plan limits come from an in-memory snapshot plus small quota leases the SDK
   renews in the background (a check costs under 50 µs). Rate limits use local token buckets; only strict quotas
   (billing-accurate) go to Valkey with GCRA, falling back to local when Valkey is slow. Usage is pre-aggregated in the
   SDK in 10-second windows before it reaches OpenMeter, cutting metering traffic by orders of magnitude.
5. **Fairness between tenants.** Per-tenant concurrency caps, weighted fair queues (NATS subjects and Temporal task
   queues per tier), adaptive concurrency limits, and priority-based load shedding (health and token refresh are shed
   last, bulk exports first). A noisy tenant in the shared pool slows only itself; a tenant that keeps hitting its caps
   is a candidate for the bridge or silo tier.
6. **`maturad` concurrency.** Go with bounded fan-out (errgroup limits, semaphores, deadlines on every call),
   `GOMEMLIMIT` and cgroup-aware `GOMAXPROCS`, CPU requests equal to limits for latency-critical pods, pgx pools sized to
   about twice the database's cores, and a fast 503 with `Retry-After` when a connection cannot be had in time.
   Every write API takes an idempotency key stored in the same transaction as the change.
7. **Events without a single leader.** Changes write to a transactional outbox; relays sharded by tenant hash publish
   to JetStream with message-ID de-duplication (exactly-once publish, per-tenant ordering). Background jobs use sharded
   leases rather than one elected leader. Temporal runs long workflows (onboarding, exports, restore tests), never
   request-path work.
8. **Postgres tuned for row-level security.** The tenant context is set with `set_config(..., true)` in the first
   pipelined statement of each transaction, so it is safe behind PgBouncer in transaction mode; policies use only
   leakproof built-in operators; every index leads with `tenant_id`; keys are UUIDv7; a missing tenant setting returns
   no rows (fail closed). PgBouncer 1.21+ with protocol-level prepared statements; small `max_connections`; separate
   CloudNativePG clusters per workload (identity, control plane, audit hot window), each with read-write and read-only
   poolers. Append-heavy tables are time-partitioned (pg_partman); big tenants graduate to bridge or silo rather than
   the pool growing without bound. Citus is not bundled (AGPL; doc 01 licence policy) but documented as an option.
9. **Audit at 50,000 events per second without a global lock.** Each tenant has its own hash chain; events are sealed
   in Merkle batches (every 200 ms or 1,000 events); once a minute a global checkpoint over all tenants is signed with
   an OpenBao transit key and written to WORM object storage in the transparency-log tile format, so anyone can verify
   inclusion without trusting the database. Transport is 16 partitioned JetStream streams (R3, file storage, async
   publish). Sinks: a Postgres hot window (COPY into daily partitions), Parquet archive on S3-compatible storage, and
   **ClickHouse (Apache-2.0) as the default search and analytics store**, shared with OpenMeter. OpenSearch becomes
   optional for teams that already run it. This changes docs 02, 07 and 09.
10. **Edge.** Envoy Gateway with native filters only (JWT, local and global rate limit, adaptive concurrency): a few
    microseconds each, against about 26 µs for WebAssembly and 81 µs for Lua. Coarse policy via a co-located
    `ext_authz` with a 25 ms timeout; WebAssembly only off the hot path.
11. **Performance is a tested contract.** SDK micro-benchmarks gate every PR (benchstat); nightly k6 at 25% scale;
    weekly full scale, soak, spike, noisy-neighbour and chaos runs, using keycloak-benchmark, `nats bench`, ghz and
    Nighthawk alongside k6. Results are published with each release.
12. **Consoles are fast too.** See doc 18 §6: route-level budgets, streaming, immutable cached assets, Core Web Vitals
    checked in CI.

## 3. Service-level objectives

Reference deployment: shared pool tier, one region, three availability zones. All [est] until TS21 measures them.

| Path | Throughput | Latency | Availability |
|---|---|---|---|
| SDK token check (cached) | in-process, unbounded | p99 < 1 ms (p50 < 20 µs) | local |
| SDK permission check (cache hit) | 100k/s cluster-wide | p99 < 0.5 ms | local |
| OpenFGA check (cache miss) | 20k/s per cluster | p99 < 5 ms | 99.95% |
| SDK entitlement / rate-limit check | in-process | p99 < 50 µs / 10 µs | local |
| Password login | 10k/s at full scale | p99 < 500 ms | 99.95% |
| SSO or passkey login | 10k/s | p95 < 200 ms, excluding the customer's IdP | 99.95% |
| Token refresh | 20k/s | p99 < 100 ms | 99.99% |
| `maturad` admin API | 5k/s | p99 < 150 ms | 99.9% |
| Audit emit to durable storage | 50k/s sustained, 150k/s burst, zero loss | p99 < 25 ms | 99.99% |
| Audit event searchable | — | p95 < 60 s | 99.9% |
| Settings and entitlement propagation to SDKs | — | p99 < 5 s | 99.9% |
| Gateway hop | ~30k RPS per core | p99 added < 0.5 ms | 99.99% |
| Tenant onboarding workflow | 50/s | p95 < 30 s | 99.9% |
| Consoles | — | LCP < 2.5 s (login < 1 s), INP < 200 ms at p75 | 99.9% |

A small install (Docker Compose on one VM) has no throughput target, only the latency targets for the SDK paths,
which do not depend on deployment size.

## 4. Open questions to measure

- No published figures exist for JetStream R3 throughput or OpenFGA latency at scale; TS21 measures both before the
  50k audit and 100k permission targets are promised publicly.
- Keycloak and OpenFGA numbers here come from search summaries of the vendors' pages; re-check against the primary
  pages before external use.
