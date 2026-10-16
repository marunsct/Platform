# 0008 — Roles are defined and assigned in Matura; apps only declare permissions

Status: proposed · 2026-10-16

## Context
ADR 0005 keeps role grants in Matura, but the roles themselves came only from each app's manifest, so renaming a
role or moving a permission between roles needed an app release. The owner asked for role management to live in
Matura entirely, and for it to work with apps written in any language.

## Decision
- An app's manifest declares its **permission catalogue**: the actions the app understands (`workflow.publish`,
  `run.start`). Only the app can define these, because only its code enforces them.
- The manifest may also declare **starter roles**. Matura stores them, and from then on roles are managed in Matura:
  operators create, edit and delete an app's roles in the operator console or API, choosing permissions from the
  catalogue (later, tenant admins add tenant-specific custom roles the same way, RL-7).
- Re-applying a manifest adds new starter roles and updates starter roles nobody has edited in Matura. It never
  changes a role created or edited in Matura, and it refuses to drop a permission that a role still uses.
- Role assignment (grants), default roles for new members and owner roles are in Matura only (ADR 0005).
- Apps receive the **expanded permissions**, not just role names: the access token carries `perms` for the calling
  app, and the contract table `matura_app_role` maps roles to permissions. An app checks a permission and never needs
  to know which role granted it.

## Alternatives
- Roles only in the manifest (previous design): every role change is an app release.
- Roles only in Matura with no catalogue: an operator could grant a permission the app does not know, and typos would
  silently grant nothing.
- Apps call Matura to check each permission: puts Matura on the request path (doc 17).

## Consequences
+ Role changes reach every app within seconds (event plus next token) without a release.
+ Apps in any language read permissions straight from the token; no SDK needed to expand roles.
− Tokens grow with the number of permissions; above 40 permissions for one app the token carries `perms_ref`
  instead and the app reads `matura_app_role` (contract §2).
