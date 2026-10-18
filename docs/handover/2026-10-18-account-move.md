# Matura handover: idea, progress and next steps

*Written 2026-10-18 so the owner (venkatesh, GitHub `marunsct`) can continue this project from another account and
merge the pending changes. A copy lives in the Platform repository at `docs/handover/2026-10-18-account-move.md`.
The engineering handover that every coding session reads first is still `HANDOVER.md` at the root of
[marunsct/Platform](https://github.com/marunsct/Platform).*

## 1. The idea

The owner has built two products that have no login or multi-tenancy of their own:

- **DevFlow** ([marunsct/DevFlow](https://github.com/marunsct/DevFlow)): an AI harness.
- **AgentCanvas** ([marunsct/AgentCanvas](https://github.com/marunsct/AgentCanvas)): a low-code canvas for building
  agents on any agent framework.

**Platform**, now named **Matura** ([marunsct/Platform](https://github.com/marunsct/Platform)), fills that gap for
these two and for any other app. It is an open-source (Apache-2.0), self-hosted *enterprise-readiness layer*: an app
adds one SDK (or speaks plain OIDC, JWT, SQL and webhooks from any language) and gets:

- **Login and identity:** sign-up, sign-in, social logins, passkeys, MFA, sessions, per-tenant SSO (OIDC/SAML), SCIM,
  built on Keycloak (unforked, extended through SPIs).
- **Multi-tenancy:** tenants and workspaces, Postgres row-level security, three data placement modes (shared tables,
  schema per tenant, database per tenant), managed by the app or by Matura.
- **User management and roles:** invitations by email, members, per-app roles defined in Matura from a permission
  catalogue in the app's manifest, tokens carrying `tid`, `roles` and `perms`, fine-grained permissions on OpenFGA.
- **Enterprise extras:** customer admin portal, operator console, tamper-evident audit log, data export and erasure,
  backups with restore tests, readiness score and trust page (SOC 2 / ISO 27001 / GDPR / EU AI Act controls), and
  identity for AI agents (on-behalf-of tokens).

Matura never hosts the app and never phones home. The owner's goal: prototypes are easy to build but hard to sell
to businesses; Matura removes the enterprise hurdles so apps are market-ready.

### Decisions the owner has made

| Date | Decision | Where |
|---|---|---|
| 2026-10-11 | Separate open-source repository, built on existing open source; renamed Tenantry → Matura | HANDOVER.md §4 |
| 2026-10-11 | App hosting dropped; focus on the enterprise-readiness layer | docs/plan/16 |
| 2026-10-16 | All three data modes, app- or platform-managed, with shared `matura_*` contract tables | ADR 0006, 0007 |
| 2026-10-16 | Roles are created and edited in Matura; integration must work from any language | ADR 0008, 0009 |
| 2026-10-17 | AgentCanvas is the first app; DevFlow moves to milestone M2 | docs/plan/21 |
| 2026-10-17 | Full autonomy to build and merge Matura; **do not touch DevFlow** until the owner says so | HANDOVER.md §2 |
| always | OSI-approved licences only (no BSL, SSPL, ELv2, AGPL bundled); never claim Matura makes anyone compliant | ADR 0002 |

## 2. Progress

### Platform (Matura), all merged into `main`

| PR | What it delivered |
|---|---|
| [#1](https://github.com/marunsct/Platform/pull/1) | The plan: `docs/plan/` 00–19, ADRs 0001–0005, research |
| [#2](https://github.com/marunsct/Platform/pull/2) | Delivery plan (doc 20), specifications 01–03, ADRs 0006–0009, first code (Go control plane `maturad`, schema with forced RLS, roles) |
| [#3](https://github.com/marunsct/Platform/pull/3) | The rest of M1 and most of M3–M6: invitations and email, token claims and Keycloak mapper, change feed and signed webhooks, placements, Python/TypeScript/Go SDKs, conformance CLI, portal at `/portal/`, operator console backend, audit log, MFA and sessions, tenant SSO, OpenFGA, SCIM, agent identity, data rights, readiness and trust page, Helm chart, backups, metrics (migrations up to 0015) |

Checked end to end on 2026-10-18 against a real Keycloak 26.4, maturad and Mailpit: invite and sign-up, sessions,
MFA reset, tenant SSO, and AgentCanvas passing all 19 conformance checks.

### AgentCanvas on Matura, merged into `main`

| PR | What it delivered |
|---|---|
| [#49](https://github.com/marunsct/AgentCanvas/pull/49) | Sign-in through Matura behind `AGENTCANVAS_AUTH_MODE=matura`, permissions mapped to its four roles, webhooks, change feed, vendored SDK, manifest (v0.27.0) |
| [#50](https://github.com/marunsct/AgentCanvas/pull/50) | Workspaces, row-level security, portal links, audit sink (v0.28.0) |

### DevFlow

Not started on Matura (sprint TS7d), on hold at the owner's request.

## 3. Pending changes and how to merge them

Nothing is open in Platform. Everything still pending is listed here, in the order to merge.

| # | Repo | PR / branch | What | Merges cleanly into `main`? | Recommendation |
|---|---|---|---|---|---|
| 1 | Platform | PR from `claude/project-thread-hr0gkg` (this handover) | Adds this document under `docs/handover/` and links it from HANDOVER.md | yes, docs only | merge |
| 2 | AgentCanvas | [#36](https://github.com/marunsct/AgentCanvas/pull/36) (draft, `claude/project-thread-wirnvh`) | AgentCanvas's side of the plan: doc 18 and ADR 0019 (identity and tenancy) | yes, docs only (4 commits) | mark ready for review, then merge; Platform's HANDOVER.md links to it |
| 3 | AgentCanvas | [#46](https://github.com/marunsct/AgentCanvas/pull/46) Dependabot | `azure/setup-helm` 4 → 5 in GitHub Actions | yes | merge |
| 4 | AgentCanvas | [#44](https://github.com/marunsct/AgentCanvas/pull/44) Dependabot | `uv` 0.12 → 0.13 in `infra/` Dockerfiles | yes | merge after a local `docker build` |
| 5 | AgentCanvas | [#47](https://github.com/marunsct/AgentCanvas/pull/47) Dependabot | Patch/minor bumps in `apps/web` (vite, playwright 1.63 → 1.64, codemirror, jsdom) | yes | merge after `npm ci && npm test` in `apps/web` |
| 6 | AgentCanvas | [#45](https://github.com/marunsct/AgentCanvas/pull/45) Dependabot | Python 3.12 → 3.14 base image for the API | yes | **major runtime bump**: build the image and run the API tests first |
| 7 | AgentCanvas | [#48](https://github.com/marunsct/AgentCanvas/pull/48) Dependabot | Node 22 → 26 base images | yes | **major runtime bump**: build and run the web and Mastra stages first |

Merge-cleanliness was checked with `git merge-tree` against each repo's `main` on 2026-10-18. The Dependabot PRs
touch different files, so merging one does not conflict with the next; Dependabot rebases them on its own.

### DevFlow branches with unmerged work (no open PRs)

These were made in other projects, not in this one, and the owner asked that this project leave DevFlow alone. They
are listed so nothing is lost when you move accounts. DevFlow's default branch is `fix-workflow-bugs`.

| Branch | Ahead of `fix-workflow-bugs` | Last commit | Note |
|---|---|---|---|
| `harness-hardening-session` | 1050 commits | 2026-10-18 | active long-running work; contains most of `live-run-23896345` |
| `live-run-23896345` | 835 commits (4 not in `harness-hardening-session`) | 2026-10-13 | the 4 extra commits: stale task id on save, pause/resume a run, undefined-name underlining, locked-test budget rule |
| `claude/intelligent-heisenberg-vpbvsr` | 4 commits | 2026-09-26 | run dump for offline auditing, Playwright runner check |

If you want them merged, open a PR for each into `fix-workflow-bugs` (start with `harness-hardening-session`, then
the 4-commit branches, which may then need conflict resolution).

### Stale branches you can delete (already merged)

Platform: `claude/project-thread-nhbr1g`, `claude/project-thread-wirnvh`. AgentCanvas: every `claude/*` branch except
`claude/project-thread-wirnvh` (it backs #36). The cloud git proxy refuses branch deletion, so do this on GitHub.

### Steps to merge from another account

1. **If the other account is a different GitHub user:** on each repo, Settings → Collaborators → add that user with
   *Write* (or *Maintain*) access, and accept the invite from the new account. If it is the same GitHub user in a
   new Claude account, just connect GitHub in the new account (claude.ai → Connect GitHub) and install the Claude
   GitHub App on the three repos.
2. **CI does not run:** GitHub Actions on this account starts no jobs (no runners since 2026-10-08), so checks show
   failed or pending without running. Verify locally (below) and merge anyway, or fix Actions billing first
   (Settings → Billing and plans → Actions).
3. **Commits need DCO sign-off** in Platform (`git commit -s`). GitHub's merge button is fine for merging PRs.
4. Merge in the order of the table above using *Create a merge commit* (what the earlier PRs used).
5. For a draft PR (#36): *Ready for review* first, then merge.

## 4. What to do next

1. **Set up the new account:** a Claude project with the three repos attached and the project instructions below;
   paste §5 into the project's memory or instructions, because memory does not move between accounts.
2. **Merge the pending changes** in §3.
3. **Close the Matura gaps** (docs/plan/21 §5), roughly in this order:
   - portal pages for SSO, SCIM, agents and audit (the APIs exist; only the UI is missing)
   - instant revocation (access tokens currently live up to 5 minutes)
   - OpenBao or a KMS for the key-encryption key, and crypto-shredding on tenant deletion
   - SCIM bulk operations and per-actor audit of SCIM changes (now recorded as `system/scim`)
   - consent screens for agents acting on a user's behalf
   - billing adapters (OpenMeter or Kill Bill) on top of the existing entitlements
   - conformance checks not yet covered: feed catch-up, version ordering, `tenant-not-ready`
4. **Release work for 1.0:** tagged pre-releases, signed release, third-party penetration test, trademark and domain
   checks for the name Matura (GitHub org `matura-dev` and npm/PyPI `matura` were free on 2026-10-11).
5. **DevFlow on Matura (TS7d)** when you decide to lift the hold: same path as AgentCanvas (Python SDK, contract
   tables, manifest with its roles, sign-in behind a flag, conformance kit).
6. Refresh the Platform README's status paragraph, which still describes the M0 state.

## 5. Working notes for the next Claude sessions

- Read `HANDOVER.md`, then `docs/plan/21` §5, before planning; update both plus `CHANGELOG.md` with every slice.
- Tests: `make test`, or `eval "$(scripts/test-postgres.sh)"` for a local Postgres 16 without Docker, then
  `go test -race ./...`. SDKs: `uv run pytest` in `sdk/python`, `npm test` in `sdk/typescript`.
- End-to-end recipe: Keycloak 26.4 tarball with the `make keycloak-ext` jar in `providers/`, Mailpit, maturad with
  OIDC on :8080; then `scripts/e2e_invite_signup.mjs`, `scripts/e2e_identity.py`, and `matura-conformance` against
  AgentCanvas.
- Keycloak realm: never list `clientScopes` in the import (it drops the built-in ones); put mappers on clients. Realm
  SMTP comes from `MATURA_KEYCLOAK_SMTP_HOST/PORT/FROM`.
- Parallel work that worked: one worker per sprint in its own git worktree, merging the lead branch in before
  handing back.

### Suggested project instructions for the new account

> This project builds Matura (marunsct/Platform), an open-source, self-hosted enterprise-readiness layer that gives
> any app login, multi-tenancy, user management, roles, SSO, audit and compliance controls. AgentCanvas
> (marunsct/AgentCanvas) runs on it; DevFlow (marunsct/DevFlow) is next but on hold until I say so. Read HANDOVER.md
> and docs/plan/21 §5 first and keep them updated. OSI-approved licences only. CI has no runners: verify locally.
