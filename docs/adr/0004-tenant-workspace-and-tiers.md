# 0004 — Tenant → workspace model, isolation tiers and RLS

Status: proposed · 2026-10-11

## Decision
A tenant is the customer account (company, or one shared tenant for individuals); a workspace is the data-isolation
unit inside it (individuals get a private personal workspace in the shared tenant). Tenants choose an isolation tier:
pool (shared database with Postgres row-level security forced, per-tenant keys), bridge (own schema/database and
namespace or vCluster), silo (own database cluster and node pool or cluster), or self-hosted. Apps get RLS through
SDK helpers and CI linting; the app's own checks remain a second layer.

## Alternatives
Database per tenant for everyone (strong but expensive at millions of tenants), application-level filtering only
(one bug leaks data), realm per tenant in Keycloak (does not scale, one user needs many accounts).

## Consequences
+ Cheap default with database-enforced isolation, and an upgrade path to full physical isolation.
− Every app table needs tenant/workspace columns and policies; migrations between tiers need tooling (Temporal workflows).
