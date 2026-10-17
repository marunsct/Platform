# Matura guides

| Guide | For |
|---|---|
| [Designing an app for Matura](designing-apps-for-matura.md) | developers building a new app on Matura or moving an existing one: what lives where, permissions, tenant-safe data models, storage modes, sync, UI, testing and a ship checklist |
| [Kubernetes](kubernetes.md) | operators installing Matura with the Helm chart, including drop-in mode with an existing Keycloak |
| [Backups](backup.md) | operators backing up and test-restoring Matura's databases |
| [Enterprise SSO](sso.md) | tenant admins connecting an OIDC or SAML identity provider (domain verification, setup, sign-in rules) and developers adding home-realm discovery; sessions and MFA reset |
| [Conformance kit](conformance.md) | anyone checking that an app, in any language, refuses bad tokens and missing permissions, keeps tenants apart and verifies signed events |

Reference: [app integration contract](../spec/03-app-integration-contract.md) · build order:
[doc 21](../plan/21-build-plan.md).
