# 0006 — Data placement: three modes, managed by the app or by Matura

Status: proposed · 2026-10-16

## Context
ADR 0004 defines isolation tiers (pool, bridge, silo) that mix data, compute and network. The owner asked for
something more concrete about data: every app on Matura must be able to keep a tenant's data in **a shared database,
a schema of its own, or a database of its own**, and for each app the database work is done **either by the app
itself or by Matura**. Apps already exist that do their own database work (AgentCanvas runs its own migrations on
its own Postgres), and new apps want Matura to do it for them.

## Decision
A **placement** records where one tenant's data lives for one app: `(tenant, app) → mode, manager, location`.

- `mode` is one of `shared` (one database, `tenant_id` on every row, Postgres row-level security forced), `schema`
  (one schema per tenant in a shared database) or `database` (one database per tenant, on a shared server or on a
  dedicated one).
- `manager` is `app` (the app creates and migrates the storage and reports the placement to Matura) or `platform`
  (Matura creates the database, schema and login roles on a database server registered with it, hands the app
  short-lived connection details, and the app runs its own migrations when Matura asks).
- The app's manifest lists the modes and managers it supports and its default. A tenant's plan can require a mode
  (for example enterprise plans require `database`).
- Matura never stores or reads app data rows. With `manager: platform` it holds credentials for the storage it
  created; with `manager: app` it holds only a label.
- Tiers in ADR 0004 stay as the commercial and infrastructure label. Pool maps to `shared`; bridge to `schema` or
  `database` on a shared server; silo to `database` on a dedicated server.

## Alternatives
- Matura always provisions: rejects existing apps that own their databases, and makes Matura a hard dependency of
  the app's storage.
- Apps always provision: every app reimplements schema and database creation, roles and credential rotation, and
  Matura cannot prove isolation or orchestrate deletion.
- One mode for every tenant: either too expensive (database per tenant for everyone) or too weak for enterprise
  buyers (shared only).

## Consequences
+ Any app can adopt Matura without moving its data; apps that want it get provisioning for free.
+ Tenant deletion, export and backup evidence can be orchestrated across apps because every placement is known.
− The SDK must route connections per tenant and cache several connection pools.
− Platform-managed placements make Matura hold database admin credentials for registered servers; they are kept
  encrypted (OpenBao when present) and never leave `maturad`.
