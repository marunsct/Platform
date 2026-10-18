# SCIM provisioning (Okta, Microsoft Entra ID)

This guide is for tenant administrators who want their identity provider (IdP) to create, update, deactivate and
remove people and groups in Matura automatically. Matura is a SCIM 2.0 service provider (RFC 7643, RFC 7644) for
each organisation. Reference: [technical specification §19](../spec/02-technical-specification.md#19-scim-20-provisioning-ts14).

SCIM handles provisioning: who belongs to the organisation. Sign-in is handled separately, by
[enterprise SSO](sso.md). Most organisations set up both, starting with SSO.

## 1. Before you start

- You need a **company** organisation (personal workspaces have no SCIM) and an **owner** account to create tokens.
  Owners and admins can map groups to roles.
- **Verify your email domains** ([SSO guide §1](sso.md#1-prove-you-own-your-email-domain)). Matura refuses to
  provision an address outside your verified domains (400 `invalidValue`), so an IdP cannot take over someone
  else's account.
- Connect your IdP for sign-in ([SSO guide §2](sso.md#2-connect-the-identity-provider)). People that SCIM creates
  get an account without a password and sign in through your IdP. The SSO connection's `default_tenant_role` is
  also the role that provisioned people join with (`member` when there is no connection).

## 2. Create a SCIM token

```sh
curl -X POST "$MATURA/v1/tenants/$TID/scim/tokens" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"name": "okta"}'
# → {"id": "…", "name": "okta", "prefix": "scim_AbCdEfG", "token": "scim_AbCdEfG…",
#    "scim_base_url": "https://matura.example.com/scim/v2/tenants/<tid>", …}
```

`token` is shown **once**. Matura keeps only a hash of it. Paste it into the IdP straight away.
`expires_at` (RFC 3339) is optional; tokens do not expire by default.

- `GET /v1/tenants/$TID/scim/tokens` lists tokens with their `prefix` and `last_used_at`.
- `DELETE /v1/tenants/$TID/scim/tokens/{id}` revokes a token immediately.
- To rotate a token: create a new one, put it in the IdP, check that `last_used_at` moves on the new token, then
  revoke the old one. An organisation can have up to five live tokens.

Every token change appears in the audit log. Changes made through SCIM are audited with actor `scim` and the
token's id.

Every SCIM request sends the token as `Authorization: Bearer scim_…`. A token only works on the base URL of its
own organisation.

## 3. Okta

1. In the Okta admin console, open **Applications → Applications → Browse App Catalog**. Add **SCIM 2.0 Test App
   (OAuth Bearer Token)**, or turn on SCIM provisioning in the app integration you already use for SSO
   (**General → App Settings → Provisioning: SCIM**).
2. Open **Provisioning → Integration** and set:
   - **SCIM connector base URL:** the `scim_base_url` from step 2.
   - **Unique identifier field for users:** `userName`.
   - **Supported provisioning actions:** Push New Users, Push Profile Updates, Push Groups.
   - **Authentication Mode:** HTTP Header. Under **Authorization**, enter the token. Okta adds the `Bearer` prefix
     for you.
3. Click **Test Connector Configuration**, then **Save**.
4. Open **Provisioning → To App** and enable **Create Users**, **Update User Attributes** and
   **Deactivate Users**.
5. Check the attribute mappings under **Provisioning → To App**:
   - Required: `userName` (the email), `givenName`, `familyName`, `email` (primary work email).
   - Optional: `employeeNumber` and `department`. These go to the enterprise extension and are stored as Keycloak
     user attributes.
6. Assign people or groups under **Assignments**.
7. To send groups, add them under **Push Groups**. Then map them to roles (step 5 below).

What Okta does, and how Matura answers:

- Okta first looks a person up with `GET /Users?filter=userName eq "…"`, then creates them with `POST /Users`.
- Unassigning or deactivating someone sends `PATCH {"op":"replace","value":{"active":false}}`.
- Okta does not delete users. People stay deactivated until you remove them in Matura or another client sends
  `DELETE`.

## 4. Microsoft Entra ID

1. In the Entra admin centre, open **Enterprise applications → New application → Create your own application**.
   Choose **Integrate any other application you don't find in the gallery (Non-gallery)**. If you already use an
   app for SSO, open that one instead.
2. Open **Provisioning → Get started** and set **Provisioning Mode** to **Automatic**.
3. Under **Admin Credentials**, set:
   - **Tenant URL:** the `scim_base_url`.
   - **Secret Token:** the token.
   Click **Test Connection**, then **Save**.
4. Under **Mappings → Provision Microsoft Entra ID Users**, check the attribute mappings:
   - `userPrincipalName` (or `mail`) → `userName`.
   - `mail` → `emails[type eq "work"].value`.
   - `givenName` → `name.givenName`, `surname` → `name.familyName`.
   - `Switch([IsSoftDeleted], …)` → `active`.
   - `employeeId` → `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber`.
   - `department` → `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`.
   Keep **Matching precedence 1** on `userName`. If `userPrincipalName` is not the person's email, map `mail` to
   `userName` instead.
5. Under **Mappings → Provision Microsoft Entra ID Groups**, keep `displayName`, `members` and `externalId`
   (`objectId`).
6. Assign users and groups under **Users and groups**. Set **Scope** to *Sync only assigned users and groups*.
   Set **Provisioning Status** to **On**.

Entra provisions on a cycle of about 40 minutes. Use **Provision on demand** to try one person straight away.

What Entra does, and how Matura answers:

- Removing someone from the app sends `active: false` (as `"False"`; Matura accepts both forms).
- After the soft-delete period, or when the user is deleted in Entra, Entra sends `DELETE /Users/{id}`.
- Group membership changes come as PATCH operations on `members`.

## 5. Map groups to app roles

Groups pushed by the IdP do nothing until you map them. A mapping gives every active member of the group (matched
by name, ignoring case) the app role, for the whole organisation:

```sh
curl -X POST "$MATURA/v1/tenants/$TID/scim/group-mappings" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"group": "Finance", "app": "ledger", "role": "approver"}'
```

`app` is the app's slug and `role` one of its roles. `GET` lists mappings and `DELETE …/group-mappings/{id}` removes
one.

- Matura keeps the grants in step with group membership. Joining, leaving, renaming or deleting a group, changing a
  mapping, deactivating or reactivating a person all add or revoke the grants the mapping made. Grants made by hand
  are never touched.
- A mapping for an app your organisation has not enabled takes effect at the next change to the group after you
  enable the app.
- Group membership is also available to apps that use [fine-grained permissions](../spec/02-technical-specification.md#18-fine-grained-permissions-ts11)
  as `group:<id>#member`.

## 6. What happens to people

| IdP action | In Matura |
|---|---|
| **Create**, email in a verified domain | If a Matura account with that email exists, it is linked; otherwise one is created (email verified, no password). The person joins the organisation with the default role and each enabled app's default role. Someone who is already a member, for example after signing in through SSO, is adopted. |
| **Create**, other domain | Refused (400). |
| **Create**, organisation full | Refused (403, "plan limit"). Raise `max_members` or remove members. |
| **Update** | Name, email (in a verified domain), employee number and department are kept in Matura. For people in your verified domains they are also copied to the sign-in account. |
| **Deactivate** (`active: false`) | The membership is deactivated, group grants are revoked and the person is signed out everywhere at once: no new tokens, and current access tokens run out within 5 minutes. The last active owner cannot be deactivated (400). |
| **Reactivate** | The membership and its group grants come back. |
| **Delete** | The person leaves the organisation and its groups, their grants are revoked and they are signed out. Their account is **erased** only when all three hold: SCIM created it, its email is in your verified domains, and the person belongs to no other organisation, their personal workspace included. Otherwise the account stays, because it is still theirs elsewhere. |

Agents and service accounts ([agents guide](agents.md)) are not SCIM users. They never appear in `/Users` and
cannot be provisioned.

## 7. Troubleshooting

| Symptom | Cause |
|---|---|
| 401 on every request | The token is wrong, revoked or expired, or belongs to another organisation's URL. Okta: do not type `Bearer` yourself. |
| 403 "this organisation is not active" | The organisation is suspended. |
| 400 `invalidValue` "…not in one of this organisation's verified domains" | Verify the domain (§1), or fix the IdP's `userName` / email mapping. |
| 409 `uniqueness` | That `userName` or `externalId` is already provisioned. The IdP should match the existing user (Okta and Entra do so through a filter). |
| 412 | The resource changed since the IdP read it (`If-Match`). The IdP retries after reading it again. |
| 400 `invalidFilter` | Only `eq` filters joined by `and` are supported (see spec §19.2). |
| 503 | Keycloak was unreachable; the IdP retries. Retries are safe: an unchanged update does not change the version, and a repeated deactivation signs out again. |

Try the endpoint by hand:

```sh
curl "$MATURA/scim/v2/tenants/$TID/Users?filter=userName%20eq%20%22ana@acme.com%22" \
     -H "Authorization: Bearer $SCIM_TOKEN"
curl "$MATURA/scim/v2/tenants/$TID/ServiceProviderConfig" -H "Authorization: Bearer $SCIM_TOKEN"
```

Bulk requests (`POST …/Bulk`, up to 1000 operations) are supported; a later operation can refer to a user or group
created earlier in the same request as `bulkId:<id>`. Each change is audited as the connection that made it
(`scim:<token name>`). Matura does not support sorting or `or`/`co`/`sw` filters; Okta and Entra need neither.
