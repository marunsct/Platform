# 0005 — OpenFGA for fine-grained permissions; roles in the control plane

Status: proposed · 2026-10-11

## Decision
Tenant and per-workspace app roles are stored in `maturad` (Keycloak's role model cannot express per-organisation
roles cleanly). Object-level permissions use OpenFGA (Apache-2.0, CNCF incubating) with a store per tenant and an
authorisation model per app from its manifest. Platform policies (admission, API guards) use OPA/Kyverno.

## Alternatives
SpiceDB (Apache-2.0, strong consistency; kept as an option), Cerbos (stateless policies), roles only (not enough
for document-level sharing).

## Consequences
+ Zanzibar-style sharing for every app without each app building it.
− One more stateful service; tuples must be kept in sync with memberships (done by `maturad` events).

## Implementation note (TS11, 2026-10-18)
Built with **one store per installation** rather than per tenant: each app has its own model in that store, and
maturad prefixes every object id with the tenant (and app types with the app's slug), so tenants and apps cannot
reach each other's tuples while installations keep one store to operate and back up. Details: technical
specification §16.
