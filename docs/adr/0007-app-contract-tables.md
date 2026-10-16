# 0007 — One shared set of contract tables in every app

Status: proposed · 2026-10-16

## Context
Apps need user and tenant data locally: to join "created by" to a name, to enforce foreign keys, and to keep
serving when Matura is unreachable (doc 17: the app never waits on Matura). Today each app invents its own copy
(AgentCanvas has `organization`, `app_user`, `membership`; DevFlow has `users` with a single role).

## Decision
Every app keeps the same small set of **contract tables**, prefixed `matura_`, created by an SDK migration and
written only by the SDK: `matura_tenant`, `matura_workspace`, `matura_user`, `matura_membership`,
`matura_role_grant`, plus bookkeeping (`matura_sync_cursor`, `matura_inbox`). Matura keeps them current through
three channels: the access token on every request (just-in-time upsert), signed events (push), and a change feed
(pull, for start-up and repair). Every change carries a monotonically increasing `version`; a write is applied only
when its version is newer, so the channels can arrive in any order.

The app's own tables reference the contract tables (`tenant_id`, `workspace_id`, `created_by → matura_user.id`)
and never add columns to them; app-specific user settings go in the app's own tables keyed by `user_id`.

## Alternatives
- Call Matura on every request: puts Matura on the app's critical path.
- Tokens only: no data for users who are not signed in (member lists, "assigned to" pickers), no deletes.
- Each app defines its own tables: no shared SDK, no shared tests, a different bug per app.

## Consequences
+ One SDK implementation, one conformance suite, the same queries in every app.
+ Apps keep working with Matura down; a missed event is repaired by the change feed.
− A copy of profile data (email, name) sits in every app database; deletion therefore goes through the
  `user.deleted` event and the change feed, and Matura records which apps confirmed it.
