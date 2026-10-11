# 06 — Hosting apps on Tenantry

> **Scope (2026-10-11):** the full-platform hosting in §2–4 is an optional module after 1.0 (doc 13, module M2).
> Version 1.0 delivers way 1 below (identity and tenancy for apps that run anywhere) and the app manifest's auth,
> roles, tenancy, events and entitlements sections.

Two ways to use Tenantry, and an operator can mix them:

1. **Identity and tenancy only:** an app runs anywhere (its own cloud, Vercel, a VM) and uses Tenantry for sign-in,
   tenants, roles, audit and billing through the SDKs.
2. **Full platform:** the app also runs on Tenantry's Kubernetes app plane, which deploys it, scales it, isolates
   tenants, backs it up and offers it in the tenant console.

## 1. App manifest

```yaml
apiVersion: tenantry.dev/v1
kind: App
metadata: { name: agentcanvas, displayName: AgentCanvas }
spec:
  auth:
    redirectUris: [https://canvas.example.com/auth/callback]
    postLogoutRedirectUris: [https://canvas.example.com/]
    publicClient: true            # SPA with PKCE
  roles:
    - { name: admin,    permissions: ["*"] }
    - { name: builder,  permissions: [workflow.read, workflow.write, workflow.run, workflow.publish] }
    - { name: reviewer, permissions: [workflow.read, inbox.decide] }
    - { name: viewer,   permissions: [workflow.read] }
  defaultRole: builder
  authorizationModel: ./fga.model           # optional OpenFGA model
  tenancy:
    tiers: [pool, bridge, silo]
    workspaceScoped: true
  events: [user.removed, workspace.deleted, tenant.suspended]   # what the app subscribes to
  entitlements:
    - { feature: runs_per_month, unit: count, meter: agentcanvas.runs }
    - { feature: seats, unit: users }
  hosting:                                   # only for the full platform
    components:
      - name: api
        image: ghcr.io/marunsct/agentcanvas-api:0.22.0
        port: 8000
        env: { AGENTCANVAS_AUTH_MODE: tenantry }
        resources: { cpu: "500m", memory: 1Gi }
        autoscale: { min: 2, max: 50, keda: { type: prometheus, query: "rate(http_requests_total[1m])", threshold: "100" } }
        health: { readiness: /healthz/ready, liveness: /healthz/live }
      - name: web
        image: ghcr.io/marunsct/agentcanvas-web:0.22.0
        port: 8080
    databases: [{ name: main, engine: postgres, version: "16", extensions: [pgvector], rls: required }]
    objectStorage: [{ name: files }]
    cache: true
    sandbox: gvisor                          # for untrusted code
    backups: { schedule: "0 * * * *", retain: 30d, pitr: true }
```

`tenantry app apply agentcanvas.yaml` validates it, creates the Keycloak client, registers roles and permissions,
loads the OpenFGA model, sets up meters and (for hosted apps) creates the deployment templates.

## 2. Deploying hosted apps

- Each app version becomes a `TenantApp` template rendered to Kubernetes manifests (Deployment, Service, HTTPRoute,
  HPA/KEDA ScaledObject, PodDisruptionBudget, NetworkPolicy, CNPG Cluster or database on a shared cluster,
  ObjectBucketClaim, ExternalSecret, ServiceMonitor) and synced by Argo CD.
- **Shared instance** (pool tier): one deployment per region serves all pool tenants.
- **Per-tenant instance** (bridge/silo): the operator instantiates the template in the tenant's namespace,
  vCluster or cluster.
- **Release rings:** internal → beta tenants → general, with automatic rollback on SLO burn (Argo Rollouts, Apache-2.0,
  canary with Prometheus analysis).
- **Database migrations:** run as a pre-sync job per instance; expand-and-contract required for zero-downtime;
  the operator runs per-tenant migrations in batches with pause/resume.
- **Custom domains:** tenants map `canvas.acme.com`; cert-manager issues certificates (HTTP-01 or DNS-01).
- **Secrets:** apps never see OpenBao root credentials; External Secrets Operator injects per-instance secrets;
  dynamic database credentials rotated by OpenBao.

## 3. What every hosted app gets for free

TLS, WAF, rate limits, sign-in, tenant routing, RLS-ready database, backups with point-in-time restore, autoscaling,
zero-downtime deploys, metrics/logs/traces with tenant labels, alerts, status page entry, audit pipeline, usage
metering, feature flags, email sending, background jobs (Temporal namespace), object storage, secrets, sandboxed code
execution.

## 4. Marketplace (later)

Operators can publish apps to their tenants as a catalogue; tenants enable an app in the console; billing plans per
app; third-party apps get scoped OAuth consent screens ("App X wants to read your workspace members").

## 5. AgentCanvas as the first app

| AgentCanvas today | On Tenantry |
|---|---|
| `security/auth.py` OIDC verifier | `tenantry` Python SDK verifier |
| `organization`, `app_user`, `membership`, invitations | tenants, workspaces, members, invitations in Tenantry; AgentCanvas keeps `organization` as its workspace row and a profile cache |
| members/audit pages | links to the tenant console; app audit stays in AgentCanvas and is forwarded to Tenantry's audit stream |
| app-level `org_scope` checks | kept as a second layer behind RLS |
| `org_data_key` envelope encryption | OpenBao transit key per tenant (migration rewraps keys) |
| own rate limits | gateway limits per tenant + its own per-deployment limits |
| Docker/Helm deploy kit | Tenantry app manifest; the existing exports keep working standalone |
