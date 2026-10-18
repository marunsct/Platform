# Enterprise single sign-on

This guide is for tenant administrators connecting their company's identity provider (IdP), and for app developers
who want "Sign in with your company account" to work. Reference: [technical specification §16–17](../spec/02-technical-specification.md#17-enterprise-sso-ts13).

## 1. Prove you own your email domain

Sign-ins through your IdP are accepted only for addresses in domains your organisation has verified. That stops an
IdP from signing in someone else's address.

```sh
curl -X POST "$MATURA/v1/tenants/$TID/domains" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"domain": "acme.com"}'
# → {"domain": "acme.com", "record_name": "_matura-challenge.acme.com",
#    "record_value": "matura-verification=Q2h…", "verified": false, …}
```

Publish a DNS TXT record named `record_name` with the value `record_value`, wait for it to propagate, then:

```sh
curl -X POST "$MATURA/v1/tenants/$TID/domains/acme.com:verify" -H "Authorization: Bearer $TOKEN"
```

A 422 `domain-not-verified` says what was found; try again later. A domain can be verified by one organisation only.
Verifying a domain also lets your owners and admins manage the sessions and second factors of people with addresses
in it, even when they belong to other organisations too (otherwise only people who belong to your organisation
alone).

## 2. Connect the identity provider

You need an owner or admin account and a verified domain. Create an application in your IdP first, using the
values Matura shows after you connect (you can delete and re-create the connection while you set it up).

### OIDC (Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak…)

```sh
curl -X POST "$MATURA/v1/tenants/$TID/sso" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "protocol": "oidc",
  "discovery_url": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "…", "client_secret": "…",
  "default_tenant_role": "member"
}'
```

`discovery_url` is the issuer or its `/.well-known/openid-configuration`. In the IdP, register the returned
`redirect_uri` (`https://<keycloak>/realms/matura/broker/t-<slug>/endpoint`) and grant the `openid email profile`
scopes. The client secret is stored encrypted and never shown again.

### SAML 2.0 (ADFS, Ping, OneLogin, JumpCloud…)

```sh
curl -X POST "$MATURA/v1/tenants/$TID/sso" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "protocol": "saml",
  "metadata_url": "https://idp.acme.com/metadata.xml",
  "email_attribute": "email", "first_name_attribute": "firstName", "last_name_attribute": "lastName"
}'
```

In the IdP, create a SAML application from the returned `metadata_url` (or enter `entity_id` and the assertion
consumer service URL `redirect_uri` by hand), send NameID in email format, sign assertions, and release the email,
first-name and last-name attributes under the names you gave (defaults `email`, `firstName`, `lastName`).

`GET /v1/tenants/$TID/sso` shows the connection again; `DELETE` removes it (and the links between accounts and the IdP).

## 3. What happens at sign-in

- The IdP must assert an email in one of your verified domains, or the sign-in is refused.
- A person signing in for the first time gets an account, or is linked to the existing account with that email.
- They join your organisation with `default_tenant_role` (member unless you chose admin or billing) and each enabled
  app's default role. Someone whose membership you deactivated is refused.
- Multi-factor authentication is your IdP's job for these sign-ins; Matura's `require_mfa` applies to password and
  social sign-ins.

## 4. Send people to their IdP (home-realm discovery)

Apps and sign-in pages ask Matura where an address signs in, then add `kc_idp_hint` to the authorisation request so
Keycloak goes straight to the IdP:

```js
const r = await fetch(`${MATURA}/v1/sso/discover?email=${encodeURIComponent(email)}`).then(r => r.json());
// {"sso": true, "idp_hint": "t-acme", "tenant": "acme"}  or  {"sso": false}
const auth = new URL(`${ISSUER}/protocol/openid-connect/auth`);
auth.search = new URLSearchParams({ client_id, redirect_uri, response_type: "code", scope: "openid",
  code_challenge, code_challenge_method: "S256", login_hint: email,
  ...(r.sso ? { kc_idp_hint: r.idp_hint, matura_tenant: r.tenant } : {}) });
location.assign(auth);
```

The endpoint is public and needs no token. Without `kc_idp_hint` people see Keycloak's normal sign-in page (tenant
IdPs are hidden there).

## 5. Sessions and second factors

| Who | Can |
|---|---|
| Everyone | `GET /v1/me/sessions`, end one (`DELETE /v1/me/sessions/{id}`), all (`DELETE /v1/me/sessions`) or all others (`?keep_current=true`); `GET /v1/me/mfa` |
| Owners, admins | for members they govern (sole organisation, or verified domain): list sessions, `POST …/members/{uid}:sign-out`, `POST …/members/{uid}:reset-mfa`; admins not for owners |

Set `require_mfa` in the [security policy](../spec/02-technical-specification.md#134-security-policies): members
without a second factor are asked to set up an authenticator app at their next password sign-in, and everyone with
one is asked for it. `session_max_age` and `idle_timeout` end sign-ins that are too old or idle when an app asks for
a new token.

## 6. Not built yet

SSO-only enforcement (no passwords for the domain, with a break-glass owner), group-to-role mapping from groups
asserted at sign-in (groups provisioned by SCIM can be mapped: see [SCIM provisioning](scim.md)), certificate
expiry warnings, a test-connection trace, the guided setup in the customer portal and a mock IdP for CI.

## Testing sign-in in CI: the mock identity provider

`cmd/matura-mockidp` is a small OpenID Connect provider for tests and CI, so you can connect a tenant's SSO, or
have an app sign in, without a real Okta or Entra. It signs RS256 tokens with a key made at start, supports the
authorization code flow (with PKCE, S256) and client credentials, and asks nothing: the authorization endpoint signs
in the person named by `login_hint`, or the first person, at once. With `-choose` it shows a pick list instead.

```sh
go run ./cmd/matura-mockidp -issuer http://localhost:9400 \
  -user 'ana@acme.test:Ana Example:engineering,admins' -user 'bo@acme.test:Bo' \
  -client 'matura:matura-secret'
```

Then connect it as the tenant's OIDC connection: the discovery URL is
`http://localhost:9400/.well-known/openid-configuration`, the client is `matura` with secret `matura-secret`, and the
groups claim is `groups`. It keeps everything in memory and has no sign-in security at all: never run it where real
people sign in. It does not speak SAML; test SAML against a real IdP's free developer tenant.
