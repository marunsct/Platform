# Functional specification — identity, tenancy, users, roles and data placement

*Version 0.1 · 2026-10-16 · proposed. Covers milestones M0–M2 of the
[delivery plan](../plan/20-end-to-end-delivery-plan.md). Later modules (audit, backup, privacy, readiness,
entitlements) keep their descriptions in [doc 16](../plan/16-product-definition.md) and get their own specifications
when their milestone starts.*

## 1. Purpose

Matura gives any app (DevFlow, AgentCanvas, or someone else's) sign-in, tenants, user management and role assignment,
and decides where each tenant's data lives, so the app does not build any of it. The app adds the Matura SDK, ships a
manifest, and keeps a small set of shared tables that Matura keeps current.

## 2. People

| Who | What they do |
|---|---|
| **End user** | signs up or is invited, signs in, switches between tenants and workspaces, manages their own profile and sessions |
| **Tenant owner / admin** | runs one customer account: invites and removes members, assigns roles per app and workspace, creates workspaces, sees which apps the tenant uses and where its data lives |
| **Operator** | runs the Matura installation: creates and suspends tenants, registers apps and database servers, sets plans and the data mode each plan requires |
| **App developer** | writes the app's manifest, integrates the SDK, runs the app's migrations |
| **The app** (machine) | verifies tokens, reads the principal, enforces roles, keeps contract tables in sync, runs migrations when a placement is ready |

## 3. Concepts

| Term | Meaning |
|---|---|
| Installation | one Matura deployment |
| Tenant | a customer account: `company`, `shared` (holds individuals) or `personal` |
| Workspace | a space inside a tenant where an app keeps data; every tenant has a default workspace |
| User | one person, one account across all tenants; credentials live in Keycloak |
| Membership | a user's place in a tenant, with a tenant role: `owner`, `admin`, `billing` or `member` |
| App | a registered application with a manifest: redirect URIs, roles, permissions, supported data modes |
| Role | an app-defined role (e.g. AgentCanvas `builder`) with a list of permissions |
| Role grant | a role given to a user (later also a group or service account) for one app, in one tenant, optionally narrowed to one workspace |
| Database server | a Postgres server registered with Matura so Matura can create databases and schemas on it |
| Placement | where one tenant's data lives for one app: mode (`shared`, `schema`, `database`) and manager (`app`, `platform`) |

## 4. Functional requirements

Requirement ids are stable; acceptance criteria are tested by the sprint named.

### 4.1 Sign-up and sign-in (ID)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| ID-1 | Users sign up with email and password and must verify the email before they can use any app | an unverified user is sent to the verify page; the link expires after 24 h | TS4 |
| ID-2 | Users sign in with email and password, Google or GitHub; a social login with a verified email that matches an existing account links to it after the user confirms | linking asks for the existing password once | TS4 |
| ID-3 | Forgotten password: reset link by email, single use, 30 min | old sessions are ended after a reset | TS4 |
| ID-4 | On first sign-in without an invitation the user chooses: personal use (joins the shared tenant with a private workspace) or a new company tenant (becomes its owner) | both paths end in the app with a valid token | TS4 |
| ID-5 | A user who belongs to several tenants picks one at sign-in (last used preselected) and can switch without signing in again | the new token carries the new tenant; the app shows that tenant's data only | TS5 |
| ID-6 | Signing out of one app ends the session for every app in the installation (single sign-out) | the other app's next request is refused within the token lifetime (5 min) | TS5 |
| ID-7 | Apps get a short-lived access token (5 min) and a rotating refresh token; tokens carry user, tenant, workspace, roles and a version (contract §2) | token under 2 KB | TS5 |
| ID-8 | Machine clients (an app's background workers) use client credentials and act on one tenant at a time | a worker token names its tenant and is refused for another tenant | TS7 |

### 4.2 Tenants and workspaces (TN)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| TN-1 | Operators and sign-up create tenants with a unique slug, name, kind and plan | duplicate slug refused with a clear error | TS2 |
| TN-2 | Every tenant gets a default workspace; admins can create, rename and archive more | an archived workspace is read-only in apps | TS2 / TS8 |
| TN-3 | Tenant states: `provisioning`, `active`, `suspended`, `deleting`, `deleted`; suspended tenants cannot sign in except owners; deleting tenants can be restored by an owner during a grace period (default 14 days) | tested per state | TS2 / TS10 |
| TN-4 | No user, admin or app can read or change another tenant's data through the API | the cross-tenant suite calls every route as tenant B with tenant A's ids and gets 404 | TS2 |
| TN-5 | Deleting a tenant asks every app with a placement to delete its data, and completes only when each app confirms or the operator overrides with a reason | the deletion record lists each app's confirmation | TS7b |

### 4.3 Users and members (UM)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| UM-1 | Tenant admins invite people by email with tenant role and app roles; delivery by set-password link (default) or temporary password with expiry, optionally to another address | invited user lands in the tenant with the chosen roles | TS6 |
| UM-2 | Invitations can be resent, revoked and expire (default 7 days) | an expired link shows "ask your admin for a new invitation" | TS6 |
| UM-3 | Admins list, search and filter members; change tenant role; deactivate (keeps history, blocks access) and remove (ends membership) | a removed member's next token refresh fails and apps receive `membership.removed` | TS2 / TS8 |
| UM-4 | A tenant always has at least one owner; the last owner cannot leave or be demoted | refused with an explanation | TS2 |
| UM-5 | Users edit their name, avatar and locale; email changes need verification | apps receive `user.updated` | TS8 |
| UM-6 | Operators deactivate or delete a user across the installation; deletion removes the profile from every app's contract tables | each app confirms; creators of records show as "deleted user" | TS7c |

### 4.4 Apps and roles (RL)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| RL-1 | Operators register an app from its manifest (`matura app apply`), which creates its OIDC client, its permission catalogue, its starter roles, its default role and its data-mode settings | applying the same manifest twice changes nothing | TS2 / TS5 |
| RL-2 | Tenants enable or disable apps; a disabled app refuses the tenant's users | token request for a disabled app fails | TS2 |
| RL-3 | Admins grant app roles to members for the whole tenant or one workspace; a member can hold several roles | grants appear in the next token and in the app's contract tables | TS2 / TS7c |
| RL-4 | New members of a tenant get each enabled app's default role unless the invitation says otherwise | tested | TS6 |
| RL-5 | Tenant `owner` and `admin` imply the app's highest role only if the manifest says so (`ownerRole`) | AgentCanvas owners are `admin`; DevFlow owners are `admin` | TS2 |
| RL-6 | Apps check permissions, not role names: the token's `perms` claim, or the SDK's `require_permission("workflow.write")`; role names are for people | example app uses permissions only | TS5 / TS7 |
| RL-7 | Custom roles per tenant (a new name with a subset of the app's permissions) | M2 | TS8 |
| RL-8 | Operators create, rename, edit and delete an app's roles in Matura, picking permissions from the app's catalogue; no app release is needed | a new role is grantable at once; a permission outside the catalogue is refused | TS2 |
| RL-9 | Role changes reach apps without a release: `app.role.*` events update `matura_app_role`, and the next token carries the new `perms` | DevFlow honours an edited role within one token lifetime (5 min) | TS5 / TS7c |
| RL-10 | Re-applying a manifest never overwrites a role created or edited in Matura, and refuses to drop a permission a role still uses | tested | TS2 |
| RL-11 | A role that someone holds, or that is the app's default role, cannot be deleted | refused with the reason | TS2 |

### 4.5 Data placement (DP)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| DP-1 | Each app declares in its manifest which modes it supports (`shared`, `schema`, `database`), which managers (`app`, `platform`) and its default | an app that only supports `shared` cannot be given a `database` placement | TS7b |
| DP-2 | Operators register database servers (host, port, admin credentials, region, labels, `dedicated` flag); credentials are stored encrypted and never shown again | a credential read returns only a fingerprint | TS7b |
| DP-3 | Plans map to a required or default mode; a tenant's placement for an app is created when the tenant enables the app | an enterprise tenant enabling DevFlow gets a `database` placement | TS7b |
| DP-4 | With `manager: platform` Matura creates the storage: shared database once per app and server, a schema per tenant, or a database per tenant, each with its own login role that cannot bypass row-level security | verified by connecting as each role | TS7b |
| DP-5 | After creating storage Matura tells the app (event `placement.provisioned`); the app runs its migrations and reports `ready`; until then the app's requests for that tenant get "tenant is being set up" | tested end to end | TS7b |
| DP-6 | With `manager: app` the app creates storage itself and registers the placement (mode and a location label, no credentials) | the operator console shows the placement | TS7b |
| DP-7 | The SDK gives the app a database session already routed and scoped to the request's tenant in every mode | the same handler code passes the cross-tenant suite in all three modes | TS7b |
| DP-8 | Moving a tenant between modes is an operator action: copy, verify row counts and checksums, switch, keep the old copy read-only for 7 days | M5 (needs workflow engine) | TS19 |
| DP-9 | Placement credentials rotate (default every 30 days) without downtime: new role, both valid during the overlap, old one dropped | M5 | TS17 |

### 4.6 Passing user information to apps (SY)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| SY-1 | Every app keeps the same contract tables (contract §3), created by one SDK migration | DevFlow and AgentCanvas have identical `matura_*` tables | TS7c |
| SY-2 | The SDK fills the tables from the token on each request when a row is missing or older than the token's version | first request by a new member creates their rows | TS7c |
| SY-3 | Matura sends signed events for every change to tenants, workspaces, users, memberships, grants and placements | signature verified; replay refused after 5 min | TS7c |
| SY-4 | Apps can read a change feed from a cursor to catch up after downtime, and a full snapshot to bootstrap | an app offline for a day catches up in one run | TS7c |
| SY-5 | Applying the same change twice, or an older change after a newer one, does nothing | property test with shuffled events | TS7c |

### 4.7 Any language or framework (IN)

| Id | Requirement | Acceptance | Sprint |
|---|---|---|---|
| IN-1 | An app integrates without any Matura SDK using standard OIDC, JWT, SQL, HTTPS and CloudEvents (contract §10) | a Node and a Java sample app reach level 2 with libraries only | TS7e |
| IN-2 | Matura publishes the contract as versioned artifacts: OpenAPI file, contract SQL for Postgres, MySQL, SQL Server and SQLite, token and event test vectors | the files exist per contract version and CI checks them against the server | TS7e |
| IN-3 | A conformance kit checks any running app from outside for token checks, permission checks, tenant isolation and event handling | the kit passes for DevFlow and the sample apps and fails for a deliberately leaky app | TS7e |
| IN-4 | Apps that cannot change their code use `matura-gateway`, which signs users in and forwards identity headers | a sample app with no auth code gets sign-in and tenants through the gateway | M3 |
| IN-5 | Official SDKs for Python, TypeScript and Go in M1; Java and .NET after M2 | each SDK passes the conformance kit | TS7, TS7e |

### 4.8 Consoles (CO), M2

| Id | Requirement | Sprint |
|---|---|---|
| CO-1 | Customer admin portal: members, invitations, roles per app, workspaces, enabled apps, data placements (read-only), audit of membership changes | TS8 |
| CO-2 | Operator console: tenants, users, apps and their roles (create, edit, delete; RL-8), database servers, plans and modes, placements and their state | TS10 |
| CO-3 | Account page for every user: profile, tenants, sessions, sign-out everywhere | TS8 |
| CO-4 | Embeddable React components for apps that prefer their own pages: tenant switcher, members table, invite dialog | TS7 / TS8 |

## 5. Main journeys

1. **Company sign-up**: visit DevFlow → "Sign up" (Keycloak page) → verify email → "Create a company" (name, slug) →
   tenant created, user is owner, DevFlow enabled with the plan's default mode → placement provisioned → DevFlow
   migrates the new tenant's storage → user lands in DevFlow as `admin`.
2. **Invite a colleague**: admin opens Members → invite `ana@acme.com` as `member` with DevFlow `operator` → Ana gets
   the email, sets a password → signs in → DevFlow receives `membership.added` before or with her first request.
3. **Switch tenant**: user in Acme and Globex picks Globex in the tenant switcher → new token for Globex → DevFlow's
   SDK routes the session to Globex's placement → only Globex data is visible.
4. **Remove a member**: admin removes Ana → refresh token family revoked → `membership.removed` → DevFlow marks her
   membership removed; her old records still show her name.
5. **Enterprise tenant with its own database**: operator puts Globex on the Enterprise plan (mode `database`) →
   Globex enables AgentCanvas → Matura creates `agentcanvas_globex` on a dedicated server and a login role → event to
   AgentCanvas → AgentCanvas runs migrations on that database → reports ready.
6. **App manages its own storage**: an app that keeps its own per-tenant databases creates one on `tenant.created`,
   then calls `PUT /v1/apps/{app}/placements/{tenant}` with `manager: app, mode: database, location: "eu-db-3"`.
7. **Delete a tenant**: owner deletes Acme → 14-day grace → `tenant.deleting` to each app → each app deletes Acme's
   data (drop schema or database, or delete rows) and confirms → Matura drops platform-managed storage, purges its
   own rows, records the confirmations.

## 6. Non-functional requirements

| Area | Requirement |
|---|---|
| Availability | apps keep serving signed-in users when Matura is down (tokens verified locally, contract tables local) |
| Latency | SDK token check p99 under 1 ms; `maturad` reads p99 under 50 ms at the reference load |
| Isolation | database-enforced in every mode: RLS in `shared`, separate schemas and roles in `schema`, separate databases and roles in `database` |
| Security | no custom crypto or password storage (Keycloak); OWASP ASVS level 2 for `maturad`; secrets encrypted at rest |
| Portability | everything speaks OIDC, JWT, SQL, HTTPS and CloudEvents, so apps in any language integrate (ADR 0009); an app can leave Matura by pointing at another OIDC provider and keeping its tables |
| Licence | OSI-approved components only (ADR 0002) |
| Accessibility | consoles meet WCAG 2.2 AA (doc 18) |

## 7. Out of scope for M0–M2

Payments, SAML/SCIM, fine-grained object permissions, audit export, backups, privacy exports, readiness, hosting
apps. They follow in M3–M6.
