# Matura guides

| Guide | For |
|---|---|
| [Designing an app for Matura](designing-apps-for-matura.md) | developers building a new app on Matura or moving an existing one: what lives where, permissions, tenant-safe data models, storage modes, sync, UI, testing and a ship checklist |
| [Kubernetes](kubernetes.md) | operators installing Matura with the Helm chart, including drop-in mode with an existing Keycloak |
| [Backups](backup.md) | operators backing up and test-restoring Matura's databases |
| [Enterprise SSO](sso.md) | tenant admins connecting an OIDC or SAML identity provider (domain verification, setup, sign-in rules) and developers adding home-realm discovery; sessions and MFA reset |
| [SCIM provisioning](scim.md) | tenant admins letting Okta, Microsoft Entra ID or another SCIM client create, update, deactivate and remove people and groups, and mapping groups to app roles |
| [Agents and service accounts](agents.md) | tenant admins creating service accounts and AI agents; developers getting agent and delegated (on-behalf-of) tokens, checking them in an app, and exposing an MCP server with Keycloak as its authorisation server |
| [Metering, quotas and billing](billing.md) | operators putting meters in plans and sending usage to Stripe, Lago or OpenMeter; developers consuming quota and reporting usage |
| [Moving from Auth0, Clerk or Keycloak](migrating.md) | operators importing people, organisations and roles with `matura import` |
| [Customer portal](portal.md) | anyone running, using or developing the customer admin portal served at `/portal/` |
| [Readiness](readiness.md) | operators checking which security controls are in place (`matura check`), recording evidence, exporting OSCAL, turning on the trust page and filling the policy templates |
| [Conformance kit](conformance.md) | anyone checking that an app, in any language, refuses bad tokens and missing permissions, keeps tenants apart and verifies signed events |

SDKs (same features in each: token verification, permission checks, webhook receiver, contract tables with the
version rule, change feed, data placement calls, test helpers):

| Language | Package | Guide |
|---|---|---|
| Python (FastAPI) | `matura` | [sdk/python](../../sdk/python/README.md) |
| TypeScript (Node.js 20+) | `@matura/sdk` | [sdk/typescript](../../sdk/typescript/README.md) |
| Go (net/http, pgx v5) | `github.com/marunsct/Platform/sdk/go` | [sdk/go](../../sdk/go/README.md) |

Any other language: the contract SQL in [docs/contract/sql](../contract/sql/README.md) and the shared
[test vectors](../contract/test-vectors.json).

Reference: [app integration contract](../spec/03-app-integration-contract.md) · build order:
[doc 21](../plan/21-build-plan.md).
