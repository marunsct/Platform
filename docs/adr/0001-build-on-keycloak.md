# 0001 — Build on Keycloak, build only the missing control plane

Status: proposed · 2026-10-11

## Context
No open-source product covers sign-in, tenants, per-app roles, enterprise SSO/SCIM, audit, admin consoles and app
hosting together. Identity providers exist and are mature; the multi-tenant control plane around them does not.

## Decision
Use Keycloak (Apache-2.0, CNCF) unforked as the identity core, plus Ory Polis (SAML bridge and SCIM) and OpenFGA.
Extend Keycloak only through public SPIs (token mappers, required actions, event listeners, REST resources, themes).
Build the control plane, consoles, SDKs and operator ourselves.

## Alternatives
Zitadel (AGPL-3.0 since v3, best native multi-tenancy; plan B behind the SDK), Authentik (enterprise features
source-available), Logto (MPL-2.0, smaller enterprise footprint), Ory stack as core (SAML/SCIM in Kratos are
commercial), forking Keycloak (maintenance burden), writing our own identity provider (security risk).

## Consequences
+ Mature, permissively licensed identity with SAML, LDAP, brokering, MFA and multi-site HA.
+ Our improvements (per-tenant roles, SCIM, onboarding actions) are open source where today's extensions are ELv2.
− Java service to operate; we must track Keycloak releases and test extensions against them.
