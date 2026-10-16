# Handover

*Last updated 2026-10-16. Read this first when starting work on Matura in a new project or session. Update it at the
end of every sprint.*

## 1. What Matura is

An open-source (Apache-2.0), self-hosted **enterprise-readiness layer**: any app adds one SDK and a few self-hosted
services and gets what business buyers demand: Identity (SSO, SCIM, MFA, passkeys on Keycloak), Tenancy (tenants,
workspaces, Postgres row-level security, per-tenant keys), Access (OpenFGA), customer Admin portal, tamper-evident
Audit, Backup with restore tests, Privacy (export, delete, residency), Readiness (SOC 2 / ISO 27001 / ISO 42001 / GDPR /
EU AI Act controls, readiness score, evidence), Entitlements, and Agent identity (MCP authorisation, on-behalf-of
tokens). It never hosts the app. Full definition: [docs/plan/16-product-definition.md](docs/plan/16-product-definition.md).

Owner's vision: building prototypes is easy, selling them to businesses is not. Matura removes the enterprise hurdles
(policies, multi-tenancy, audits, backups) so apps are market-ready, while users keep full control (open source,
self-hosted, open standards, nothing phones home).

## 2. Status

- The plan is draft PR [#1](https://github.com/marunsct/Platform/pull/1) (branch `claude/project-thread-wirnvh`):
  `docs/plan/` 00–19, `docs/adr/` 0001–0005, `docs/research/`.
- 2026-10-16: the owner asked for the end-to-end plan, functional and technical specifications, and to start
  development. Branch `claude/project-thread-nhbr1g` (stacked on PR #1) adds `docs/plan/20` (delivery plan, which
  re-orders doc 13 so DevFlow and AgentCanvas sign in early), `docs/spec/01–03`, ADRs 0006 (data placement: shared,
  schema or database, managed by the app or by Matura) and 0007 (shared `matura_*` contract tables), and the first
  code: TS1 and most of TS2.
- **Built (TS1/TS2):** Go module; `maturad` with tenants, workspaces, members (last-owner rule), apps from manifests,
  roles, grants, tenant apps with placement selection (plan-required mode wins); Postgres schema with forced RLS on
  tenant-owned tables (fails closed), version sequence and outbox; dev and OIDC authentication; problem+json;
  If-Match; Compose (Postgres, Keycloak realm, Mailpit, maturad); CI workflow; tests incl. the cross-tenant suite.
- 2026-10-16 (later): the owner asked for role definitions to be managed in Matura and for integration to work from
  any language. ADR 0008 (permission catalogue in the manifest, roles created/edited/deleted in Matura, `perms`
  claim, `matura_app_role` contract table) and ADR 0009 (levels 0–3 over OIDC, JWT, SQL, HTTPS, CloudEvents; SDKs
  optional; conformance kit; sprint TS7e) are written, and role management is built (migration 0002, role API).
- **Left in TS2:** idempotency keys, OpenAPI document, outbox relay (TS7c), operator endpoints for users, plans and
  database servers.
- **Next:** TS4-lite sign-in on Keycloak, TS5 token mapper, TS6 invitations, TS7 Python SDK, TS7b provisioning,
  TS7c contract sync, TS7d DevFlow (doc 20 §3).
- `main` holds LICENSE, SECURITY.md, CONTRIBUTING.md.

## 3. Where to read

| Need | Document |
|---|---|
| What and why | 16 product definition, 19 research findings |
| How it performs | 17 performance and concurrency (rule: the app never waits on Matura) |
| How it looks | 18 UI and design system |
| What to build, in order | 20 delivery plan (order), 13 roadmap (sprint contents) (TS1–TS27 to 1.0; TS3 design system first; TS15 agent identity; TS21 performance; TS26 AgentCanvas on Matura) |
| Component choices and licences | 01 landscape, ADRs 0001–0005 |
| Open decisions | 14 risks and decisions |

## 4. Decisions already made by the owner

- 2026-10-11: separate open-source repository (this one), built on existing open source rather than from scratch.
- 2026-10-11: narrower 1.0 focus adopted; later refined to the enterprise-readiness layer; app hosting dropped.
- 2026-10-11: renamed from "Tenantry" to **Matura**. GitHub org `matura-dev` and npm/PyPI `matura` were free on that
  date; trademark (classes 9/42) and domain checks are still open.
- 2026-10-12: Matura moves into its own Claude project, separate from AgentCanvas.

## 5. Rules

- Licence policy: OSI-approved licences only; no BSL, SSPL, ELv2 or other source-available components (Zitadel is AGPL
  since v3, Phase Two Keycloak extensions are ELv2, MinIO community edition is archived, Citus is AGPL so not bundled).
- Keycloak stays unforked; extend through SPIs and keep custom extensions few.
- Never claim Matura makes anyone compliant: it adds controls and evidence; auditors decide.
- Sprints are numbered `TS<n>`. Each ends with tests green, docs updated, a changelog entry, a tagged pre-release and
  this file updated.
- Commits and PRs end with the attribution lines the session provides.

## 6. Relationship to AgentCanvas

AgentCanvas ([marunsct/AgentCanvas](https://github.com/marunsct/AgentCanvas)) is Matura's first app and lives in its own
project. Its side of the plan is `docs/agent-canvas-spec/18-identity-and-tenancy-plan.md` and
`docs/adr/0019-identity-and-tenancy-platform.md` (draft PR marunsct/AgentCanvas#36). AgentCanvas keeps one track of its
own (T5: workspace columns and RLS on its tables); everything else becomes Matura sprint TS26.

## 7. Suggested project instructions for the new Claude project

> This project builds Matura (repository marunsct/Platform), an open-source, self-hosted enterprise-readiness layer
> for any app. Read HANDOVER.md first and keep it updated at the end of every sprint. Follow the plan in docs/plan
> (roadmap: doc 13) and the licence policy (OSI only). Do not implement or merge anything the owner has not approved.
> AgentCanvas (marunsct/AgentCanvas) is the first app and lives in a separate project.

## 8. Known environment quirks (from the AgentCanvas project)

- GitHub Actions had no runners from 2026-10-08; PR checks failed without running. Verify locally.
- The cloud git proxy prints "This repository moved" on push to `marunsct/Platform`; the push still succeeds.
- The cloud git proxy refuses remote branch deletion.
