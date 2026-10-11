# 02 — Architecture

## 1. Big picture

```
                              Users, admins, developers (browser, CLI, SDK)
                                             |
                         Envoy Gateway (TLS, Coraza WAF, rate limits, ext-authz)
          +-------------------+-------------------+--------------------+-------------------+
          |                   |                   |                    |                   |
   Keycloak cluster     maturad API        Consoles (static)    Ory Polis           Hosted apps
   (login, tokens,      (control plane)      tenant / platform /  (SAML bridge,       (AgentCanvas,
    MFA, brokering)          |               account / developer   SCIM endpoints)     your next app)
          |                  |                                         |                    |
   Infinispan        +-------+-------+--------+---------+---------+    |          matura SDK in each app
          |          |       |       |        |         |         |    |          (verify token, roles,
     Postgres     Postgres OpenFGA  OpenBao  NATS    Temporal  OpenMeter|           RLS context)
     (keycloak)   (control) (authz) (keys)  (events) (workflows)(usage) |
                                                                       |
         All state backed up (CNPG + Barman to object storage, Velero, OpenBao snapshots)
         Observability: OpenTelemetry -> Prometheus/VictoriaMetrics, Jaeger, OpenSearch
```

Planes:

| Plane | What runs there | Scaling unit |
|---|---|---|
| **Edge** | Envoy Gateway, WAF, certificates, DDoS rate limits | replicas per region |
| **Identity plane** | Keycloak + Infinispan + its Postgres; Ory Polis | Keycloak cluster per region (multi-site) |
| **Control plane** | `maturad` API, workers, Temporal, OpenFGA, OpenBao, NATS, OpenMeter, consoles | stateless replicas + HA stores |
| **App plane** | the apps tenants use; shared pools or per-tenant instances | namespace, vCluster or dedicated cluster per tenant (doc 04) |
| **Management plane** | `matura-operator`, Argo CD, Cluster API, backups, observability | one per installation (plus per region) |

## 2. Components we build

| Component | Language | Responsibility |
|---|---|---|
| `maturad` | Go | REST + gRPC API (OpenAPI 3.1), tenants, workspaces, members, invitations, apps, roles, entitlements, audit, webhooks, SCIM fan-out, domain verification, data export/delete; transactional outbox to NATS |
| `matura-worker` | Go (Temporal workers) | long-running flows: tenant provisioning (DB, namespace, keys, Keycloak org, OpenFGA store), onboarding emails, offboarding, crypto-shredding, export, region moves |
| `matura-operator` | Go (controller-runtime) | CRDs `Tenant`, `TenantApp`, `TenantDatabase`, `Installation`; reconciles dedicated resources, backups, upgrades |
| Keycloak extensions | Java | token mapper (tenant, workspace, app roles), required actions (temporary password with expiry, verify alternate address, accept terms), event listener → NATS, tenant-scoped admin REST, risk-based login hooks, themes |
| Consoles | React + TypeScript | tenant admin, platform admin, account portal, developer portal (doc 05) |
| SDKs | Python, TypeScript, Go; React UI kit | doc 11 |
| CLI `matura` | Go | install, tenants, apps, backups, support bundle |
| OpenTofu provider | Go | manage tenants, apps, roles as code |

Why Go for the control plane: the Kubernetes ecosystem (operator, Cluster API, client libraries) is Go; single static
binaries are easy for others to host; low memory at scale. Trade-off: AgentCanvas is Python, so we keep a first-class
Python SDK and keep the control plane's API language-neutral (OpenAPI, gRPC, CloudEvents).

## 3. Core data model (control-plane database)

```
installation (1) ── region (n)
tenant(id, slug, name, kind: company|shared|personal, status: active|suspended|deleting,
       plan_id, home_region, isolation_tier: pool|bridge|silo, kms_key_ref, created_at)
  ├─ workspace(id, tenant_id, name, region, isolation_tier_override)
  ├─ tenant_domain(domain, verification_token, verified_at, routing: sso|invite|open)
  ├─ tenant_idp(id, tenant_id, type: oidc|saml, keycloak_alias, polis_connection_id, settings)
  ├─ tenant_policy(mfa_required, password_policy, session_idle_s, session_max_s, ip_allowlist,
  │                allowed_login_methods, data_retention_days, audit_export_target)
  ├─ membership(tenant_id, user_id, tenant_role: owner|admin|billing|member, status, joined_at)
  ├─ invitation(id, tenant_id, email, delivery: link|temp_password, deliver_to, roles, expires_at,
  │             state: pending|accepted|revoked|expired)
  ├─ grant(subject: user|group|service_account, workspace_id, app_id, role)
  ├─ group(id, tenant_id, name, source: local|scim|idp) ── group_member
  ├─ service_account(id, tenant_id, workspace_id, name, roles, expires_at) ── api_key(hash, prefix, last_used)
  ├─ tenant_app(tenant_id, app_id, state, instance_ref, plan limits)
  └─ entitlement(tenant_id, feature, limit, used, period)
user(id = keycloak sub, email, display_name, locale, status)       # profile cache; credentials stay in Keycloak
app(id, name, client_id, manifest, roles[], default_role, owner)
audit_event(id, ts, tenant_id, actor, action, target, ip, ua, result, detail, prev_hash, hash)
outbox(id, topic, payload, created_at, sent_at)
webhook_endpoint(id, tenant_id|app_id, url, secret_ref, events[]) ── webhook_delivery
```

Every tenant-owned row carries `tenant_id`; RLS is on for the control plane itself (doc 04).

## 4. Tokens

- Access token (JWT, RS256/ES256, 5 minutes) issued by Keycloak with claims: `sub`, `email`, `email_verified`,
  `tid` (tenant), `wid` (current workspace, when the client asks for one), `roles` for the calling app's client
  scoped to that workspace (from the Matura mapper, cached), `amr`/`acr` (MFA level), `sid`.
- Large role sets are not put in tokens; the SDK fetches grants from `maturad` with a 60 s cache invalidated by
  events.
- Refresh tokens rotate; reuse detection revokes the family. Token exchange (RFC 8693) for service-to-service calls
  between apps on behalf of a user. DPoP (RFC 9449) optional for public clients.

## 5. APIs

- **Public REST API** `/v1/...` (OpenAPI 3.1, JSON, problem+json errors, cursor pagination, `If-Match` optimistic
  locking, idempotency keys on POST). Main resources: tenants, workspaces, members, invitations, groups, apps,
  grants, service accounts, API keys, domains, identity providers, policies, sessions, audit events, entitlements,
  usage, webhooks, exports.
- **Admin API** `/admin/v1/...` platform-only (tenants lifecycle, impersonation, plans, feature flags).
- **SCIM 2.0** `/scim/v2/{tenant}/Users|Groups` (served by Ory Polis or `maturad`, writes through `maturad`).
- **Check API** `/v1/check` (is subject S allowed relation R on object O, via OpenFGA), batch check, list objects.
- **gRPC** mirror of the hot paths (grants, check) for low latency.
- **Events** CloudEvents 1.0 on NATS subjects `matura.<tenant>.<type>` and signed webhooks (HMAC-SHA256,
  timestamps, retries with backoff, dead-letter, replay from the console).
- Versioning: URL major version; additive changes only within a major; deprecations announced two minor releases
  ahead with `Sunset` headers.

## 6. Deployment shapes

| Shape | For | How |
|---|---|---|
| **Evaluate** | laptop, demo | `docker compose up`: Keycloak, maturad, consoles, Postgres, Valkey, NATS, Mailpit, SeaweedFS, OpenFGA, OpenBao (dev) |
| **Small** | up to ~10k users | one Kubernetes cluster, Helm chart, CNPG with 3 instances, single region, daily+PITR backups |
| **Standard** | up to ~1M users | one region across 3 zones, autoscaling, separate node pools for identity, control and apps, Capsule/vCluster tenancy |
| **Hyperscale** | millions of users, many regions | multi-cluster, per-region identity and control planes, global tenant directory, NATS super-cluster, Karmada or Argo CD ApplicationSets across clusters, silo clusters for large tenants (doc 08) |
| **Air-gapped** | regulated on-prem | offline bundle (images, charts, SBOMs, signatures), internal registry, Talos/RKE2, local KMS (OpenBao + HSM via PKCS#11) |

## 7. Repository layout

```
matura/
  cmd/ maturad, matura-worker, matura-operator, matura (CLI)
  internal/ ...                         # Go packages
  api/ openapi.yaml, proto/
  keycloak/ extensions/ (Java, Maven), themes/ (Keycloakify), realm/ (realm-as-code)
  console/ (React monorepo: tenant-admin, platform-admin, account, developer, ui-kit)
  sdk/ python/, typescript/, react/, go/
  deploy/ helm/, compose/, operator CRDs, terraform/opentofu modules, airgap/
  docs/ plan/, adr/, user/, admin/, developer/, security/
  examples/ hello-app (FastAPI), hello-app-node
  tests/ e2e (Playwright), load (k6), chaos (Litmus/Chaos Mesh), security
```
