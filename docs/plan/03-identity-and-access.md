# 03 — Identity and access

## 1. Users and sign-in methods

| Method | Default | Detail |
|---|---|---|
| Email + password | on | email is the user name; verification link before first use; password policy per tenant (doc §5) |
| Google, GitHub, Microsoft, Apple, GitLab, any OIDC | Google and GitHub on (platform admin adds client ids) | Keycloak identity brokering; only verified emails link to an existing account; account linking needs re-authentication |
| Passkeys (WebAuthn) | on | passwordless sign-in and as second factor |
| Magic link / email OTP | off | optional for consumer apps |
| Enterprise SSO (SAML 2.0, OIDC) per tenant | per tenant | doc §7 |
| LDAP / Active Directory | per tenant (on-prem) | Keycloak user federation, read-only or sync |
| Service accounts and API keys | per workspace | doc §10 |

One person = one Keycloak user across all apps and tenants. Profile (name, locale, avatar) lives in Keycloak and is
cached by `tenantryd`.

## 2. Self-service sign-up

1. `/signup` (themed Keycloak page): email + password, or a social button. CAPTCHA (self-hosted, e.g. ALTCHA, MIT)
   appears only when the risk engine sees abuse (rate, IP reputation, disposable domains).
2. Verify email (link valid 24 h, single use).
3. First-sign-in screen (Tenantry required action): **Just me** → joins the platform's **shared tenant** (kind
   `shared`) and gets a private personal workspace; **My organisation** → name, optional domain → new tenant (kind
   `company`), the user becomes `owner`, first workspace created, trial plan applied.
4. If the email's domain is verified by a tenant with routing `sso` or `invite`, the user is sent to that tenant's
   SSO or told to ask their admin (no stray personal accounts for employees).
5. Platform sign-up modes: open, invite-only, closed, domain allow-list, domain block-list; terms acceptance with
   version tracking.

## 3. Onboarding by an admin (email = user name)

| Step | Detail |
|---|---|
| Enter | email, display name (optional), tenant role, workspace and app roles, groups |
| Delivery | **set-password link** (default; single use, 72 h) or **generated temporary password** (20 chars from a CSPRNG, stored only in Keycloak as a *temporary* credential so the first sign-in forces a change; expires after 72 h unused via a scheduled Temporal job) |
| Deliver to | the user's own email (default) or **another address** (e.g. the admin's, to hand over); then the user's own email stays unverified and Keycloak's verify-email action runs at first sign-in |
| First sign-in | change password (policy-checked, breached-password check), enrol MFA if the tenant requires it, accept terms, land in the workspace |
| Bulk | CSV upload (email, roles, groups) with a dry-run preview; API and SCIM for automation |
| Manage | resend, revoke, change roles before acceptance, expiry reminders, audit of every send (never the password itself) |
| New tenant | the platform admin onboards an owner the same way; the owner gets full rights over the tenant |

Emails go through `tenantryd`'s outbox → SMTP relay (any provider, or Postal), templates per tenant brand and locale,
SPF/DKIM/DMARC checks in the platform console, bounce and complaint handling.

## 4. Sessions

- Keycloak SSO session per browser; app sessions are tokens. Per-tenant **idle timeout** (default 30 min for admin
  consoles, 8 h for apps) and **maximum lifetime** (default 12 h; "remember me" up to 30 days if the tenant allows).
- Users see their sessions and devices (browser, OS, IP, location, last active) and sign out any or all.
- Admins see members' sessions and revoke them; removing a member, suspending a user, changing a password or
  resetting MFA revokes all their sessions and refresh tokens. Back-channel logout to every app (OIDC back-channel
  logout) plus a revocation event on NATS so SDKs drop cached grants immediately.
- Step-up authentication: apps can require `acr=mfa` for sensitive actions (SDK helper `require_mfa()`).
- Concurrent session limit per tenant (optional).

## 5. Credentials and account protection

| Control | Default |
|---|---|
| Password hashing | Keycloak PBKDF2-SHA512 (210k+ iterations) or Argon2 provider |
| Password policy (tenant may tighten) | min 12 chars, not email or name, last 5 not reused, breached-password check against a self-hosted k-anonymity Pwned Passwords mirror |
| Brute force | per-user temporary lockout after 5 failures (15 min, growing), permanent after repeated waves; per-IP rate limit at the gateway; credential-stuffing detection (many users, one IP) |
| MFA | TOTP, WebAuthn/passkeys, recovery codes (10, single use); tenant can require MFA for everyone or admins only; admin MFA reset requires a second admin (four-eyes) in strict mode |
| Risk signals | new device, impossible travel (IP-to-country from DB-IP Lite, CC-BY-4.0), Tor exit nodes; actions: notify, require MFA, block |
| Account recovery | email link + MFA; if MFA lost, recovery codes or admin-assisted reset with audit |
| Notifications | new sign-in from a new device, password changed, MFA changed, email changed (to old and new address) |

## 6. Roles

Three levels, all managed by `tenantryd` (Keycloak keeps credentials, not per-tenant roles):

| Level | Roles (defaults) | Notes |
|---|---|---|
| Platform | `platform_owner`, `platform_admin`, `platform_support`, `platform_auditor`, `platform_billing` | operators of the installation; support has no data access without consented impersonation |
| Tenant | `owner`, `admin`, `security_admin`, `billing`, `auditor`, `member` | owner can delete the tenant and transfer ownership; at least one owner always |
| App (per workspace) | declared by each app's manifest (AgentCanvas: `admin`, `builder`, `reviewer`, `viewer`) | tenant `owner`/`admin` are implicit app admins unless the tenant turns it off |

Custom roles: tenants can define roles from an app's permission list (the manifest lists permissions; roles are
bundles). Group-based grants: groups from SCIM or the IdP map to roles.

## 7. Enterprise SSO (per tenant, self-service)

1. Tenant admin opens *Single sign-on*, picks SAML or OIDC, follows a guided setup per IdP (Okta, Microsoft Entra ID,
   Google Workspace, Ping, ADFS, JumpCloud, OneLogin, generic): Tenantry shows SP metadata/ACS/entity id, the admin
   uploads IdP metadata or enters discovery URL.
2. Created as a Keycloak identity provider bound to the tenant's Organization (OIDC and SAML), or through Ory Polis
   when the tenant needs SAML features Keycloak's broker lacks; signed assertions required, encrypted assertions
   optional, clock skew 2 min, certificate expiry warnings 30/7/1 days ahead.
3. **Domain verification** (DNS TXT `_tenantry-challenge.<domain>`), then **home-realm discovery**: users typing an
   email at that domain go straight to their IdP.
4. **Just-in-time provisioning** with attribute mapping (email, name, groups, department); group-to-role mapping.
5. Enforcement: "SSO only" disables passwords for the domain's users (break-glass owner account kept, MFA-required).
6. Test connection button with a readable SAML/OIDC trace; per-connection audit.
7. IdP-initiated SAML allowed only with relay-state checks; single logout optional.

## 8. SCIM 2.0 directory sync

- Endpoint per tenant `/scim/v2/{tenant}` with a bearer token per connection (rotatable), served by Ory Polis or
  `tenantryd`, written through `tenantryd` so audit, roles and Keycloak stay consistent.
- Users: create, update, deactivate (revokes sessions), delete (after retention). Groups: create, rename, membership.
- Tested against Okta and Entra ID SCIM validators; rate limits per tenant; conflict handling with JIT users
  (match by `externalId`, then verified email).
- Deprovisioning SLA: session revoked within 60 s of a SCIM deactivate.

## 9. Fine-grained permissions (OpenFGA)

- One OpenFGA store per tenant (or one store with tenant-prefixed objects for small installs); authorisation model
  per app supplied in the app manifest, e.g. `document: viewer, editor, owner from parent folder`.
- `tenantryd` writes relationship tuples for workspace membership and grants; apps write their own object tuples
  through the SDK (`authz.grant(user, "editor", doc)`), and check with `authz.check(...)` (cached, consistency token
  for read-after-write).
- Admin console shows "who has access to X" and "what can user Y do" using `list_objects` / `list_users`.

## 10. Service accounts, API keys and machine-to-machine

- Service accounts per workspace with roles and expiry (max 1 year by policy); OAuth 2 client-credentials via a
  Keycloak client per service account, or **API keys** (`tnt_<prefix>_<secret>`, stored as SHA-256 hash, shown once,
  last-used tracking, IP restrictions, rotation with overlap).
- Personal access tokens for users (scoped, expiring), disabled for tenants that forbid them.
- Workload identity: apps running on the platform get tokens via Kubernetes service-account token projection
  exchanged at Keycloak (RFC 8693), no static secrets.
- Webhook signing secrets and app-to-app calls use token exchange with audience restriction.

## 11. Impersonation and support access

- `platform_support` requests access to a tenant with a reason; the tenant owner approves (or policy auto-approves
  for low tiers); time-boxed (default 30 min), read-only by default; a banner shows in the app; every action is
  tagged `impersonated_by` in both audit logs; tenants can disable support access entirely.
- Break-glass for `platform_owner`: requires two people (approval in the platform console), alerts the tenant owner.

## 12. Privacy and consent

- Consent records for terms and privacy policy versions; marketing consent separate.
- User data export (profile, memberships, audit about them) and account deletion (self-service, with grace period);
  apps receive `user.deleted` events and must erase.
- Data minimisation in tokens; PII fields marked in the schema and excluded from logs.
