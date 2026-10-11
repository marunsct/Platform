# Architecture decision records

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-build-on-keycloak.md) | Build on Keycloak, unforked, extended through its SPIs; build only the missing control plane | proposed |
| [0002](0002-licence-policy.md) | Apache-2.0 for our code; only OSI-approved components | proposed |
| [0003](0003-control-plane-in-go.md) | Control plane, operator and CLI in Go | proposed |
| [0004](0004-tenant-workspace-and-tiers.md) | Tenant → workspace model, pool/bridge/silo isolation tiers, Postgres RLS | proposed |
| [0005](0005-openfga-for-permissions.md) | OpenFGA for fine-grained permissions; roles in the control plane | proposed |

Format: context, decision, alternatives, consequences. Status moves to `accepted` when the owner approves the plan.
