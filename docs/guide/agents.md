# Agents and service accounts

This guide is for tenant administrators who give scripts, integrations and AI agents their own identity, and for app
developers whose apps accept calls from them, including apps that expose an MCP server. Reference: [technical
specification §20](../spec/02-technical-specification.md#20-agent-identity-ts15) and [contract
§2](../spec/03-app-integration-contract.md#2-the-access-token).

Two kinds of non-human principal belong to a tenant:

| Kind | For | Acts |
|---|---|---|
| `service` | scripts, integrations, CI jobs | as itself |
| `agent` | AI agents | as itself, or for a person who delegates to it |

Each is a Keycloak confidential client. Its tokens carry the tenant, roles and permissions like a person's, plus
`kind`. A token an agent gets for a person carries the person as `sub`, the agent in `act`, and only the permissions
both of them have.

## 1. Create an agent

Owners and admins create agents. Grants work as for people: name an app and one of its roles.

```sh
curl -X POST "$MATURA/v1/tenants/$TID/agents" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{
       "kind": "agent", "name": "Report bot", "description": "Writes the weekly report",
       "expires_at": "2027-01-31T00:00:00Z",
       "grants": [{"app": "agentcanvas", "role": "runner"}]}'
# → {"id": "9a1a…", "client_id": "agent-3f9c2a1b7d4e", "client_secret": "kq7…",
#    "token_endpoint": "https://id.example.com/realms/matura/protocol/openid-connect/token", "grants": […], …}
```

- **The secret is shown once.** Store it in the agent's secret store. Matura does not keep a copy.
- `owner_id` is the person responsible for the agent. The default is you.
- After `expires_at`, no token is issued for the agent or on its behalf.
- Add or remove roles later with `POST /v1/tenants/{tid}/grants` (`user_id` = the agent's `id`) and `DELETE …/grants/{id}`.
- The plan's `max_agents` limits how many agents and service accounts a tenant has. Agents do not count as members.

Manage it:

| Do | Call |
|---|---|
| List or read | `GET …/agents`, `GET …/agents/{id}` |
| Rename, change owner or expiry | `PATCH …/agents/{id}` with `name`, `description`, `owner_id`, `expires_at` (null removes it) |
| **Stop it now** (kill switch) | `PATCH …/agents/{id}` with `{"status": "deactivated"}`; `"active"` turns it back on |
| Rotate the secret | `POST …/agents/{id}:rotate-secret` (the old secret stops at once) |
| Delete | `DELETE …/agents/{id}` |

Deactivation stops new tokens at once. This covers the agent's own tokens and tokens for people it acts for. Tokens
already issued expire within 5 minutes. Every change is in the tenant's audit log (`agent.*`).

## 2. The agent's own token

Use the client-credentials grant. Name the app with `matura_app`, `audience` or `resource`. Leave it out when the
agent has roles in one app only.

```sh
curl -s "$TOKEN_ENDPOINT" -d grant_type=client_credentials \
     -d client_id=agent-3f9c2a1b7d4e -d client_secret="$SECRET" -d matura_app=agentcanvas
```

```json
{"sub": "9a1a…", "azp": "agent-3f9c2a1b7d4e", "aud": "agentcanvas", "kind": "agent",
 "tid": "…", "tenant": "acme", "troles": ["member"], "roles": ["runner"], "perms": ["run.start", "workflow.read"]}
```

## 3. Acting for a person (delegation, RFC 8693)

The agent exchanges a person's access token for one in that person's name. It uses Keycloak's standard token
exchange, which Matura turns on for every agent client:

```sh
curl -s "$TOKEN_ENDPOINT" -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d client_id=agent-3f9c2a1b7d4e -d client_secret="$SECRET" \
     -d subject_token="$USER_ACCESS_TOKEN" -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
     -d requested_token_type=urn:ietf:params:oauth:token-type:access_token -d audience=agentcanvas
```

```json
{"sub": "<Ana>", "azp": "agent-3f9c2a1b7d4e", "aud": "agentcanvas", "kind": "human",
 "act": {"sub": "9a1a…", "kind": "agent", "client_id": "agent-3f9c2a1b7d4e"},
 "roles": ["viewer"], "perms": ["workflow.read"]}
```

- **Permissions are the intersection.** If Ana may read and write workflows and the agent may read workflows and
  start runs, the token allows reading workflows only. An owner's `*` gives the agent's own permissions. The token
  has the tenant role only when both share it, so it has none for an owner. Delegated tokens never manage the tenant.
- **Ana must be an active member of the agent's tenant.** Her organisation's session limits still apply.
- **Keycloak lets the agent exchange a token only if the agent is in that token's audience.** There are two ways:
  - The person signs in to the agent's client.
  - The app's client adds the agent as an audience: an `oidc-audience-mapper` with
    `included.client.audience` set to the agent's client id.

  Consent screens are not built yet. Until they are, set this up only for agents the tenant trusts.

## 4. Checking agent tokens in an app

Nothing changes for permission checks. Check `perms` as for a person. The SDKs also expose who is acting:

```python
p = verifier.verify(token)
p.kind            # "human", "service" or "agent"
p.actor           # Actor(sub=…, kind="agent", client_id=…) on a delegated token, else None
p.is_delegated
```

```ts
p.kind; p.actor?.sub; p.isDelegated;
```

```go
p.Kind; p.Actor /* *matura.Actor or nil */; p.IsDelegated()
```

Record both identities in your own audit trail. For example: "Report bot (agent) for Ana: exported workflow 12".
Agents appear in `matura_user` with their `kind`, and in `matura_membership` and `matura_role_grant` like people.
Other languages read the `kind` and `act` claims directly. The [test vectors](../contract/test-vectors.json) include
an agent token and a delegated token.

maturad's own audit log records delegated calls to its API with `actor.kind: "agent"`, `actor.id` = the agent, and
`actor.on_behalf_of` = the person. Filtering by the person's id (`?actor=`) also finds what agents did for them.

## 5. MCP servers: Keycloak as the authorisation server

An app that exposes an MCP server, or any API that agents call, is an OAuth protected resource. MCP clients find out
where to get tokens from the resource's metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)).

1. **Name the resource in the app's manifest.** Then a token request with `resource=<its URL>` gets a token for the
   app, with the app's client id in `aud`:

   ```json
   {"slug": "agentcanvas", "auth": {"redirect_uris": ["…"], "resources": ["https://canvas.example.com/mcp"]}, …}
   ```

2. **Serve the metadata** at `/.well-known/oauth-protected-resource` plus the resource's path, and point 401 answers
   at it. The SDKs build both:

   ```python
   from matura import protected_resource_metadata, metadata_url, www_authenticate

   RESOURCE = "https://canvas.example.com/mcp"
   ISSUER = "https://id.example.com/realms/matura"

   @app.get("/.well-known/oauth-protected-resource/mcp")
   def prm():
       return protected_resource_metadata(RESOURCE, [ISSUER], resource_name="AgentCanvas MCP")

   # on a missing or invalid token:
   raise HTTPException(401, headers={"WWW-Authenticate": www_authenticate(RESOURCE)})
   # → Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp"
   ```

   TypeScript: `protectedResourceMetadata(resource, [issuer])`, `wwwAuthenticate(resource)`, `metadataUrl(resource)`.
   Go: `matura.NewResourceMetadata(resource, issuer)`, `matura.WWWAuthenticate(resource, matura.Challenge{})`,
   `matura.MetadataURL(resource)`.

3. **Verify tokens as usual.** Use the app's client id as the audience (the SDK `Verifier`), then check `perms`. A
   token missing a permission gets 403. You may add `error="insufficient_scope"` to the challenge.

The client reads the metadata and then Keycloak's discovery document at
`<issuer>/.well-known/openid-configuration`. It gets a token in one of two ways:

- as the agent itself, with client credentials;
- for a person, with the authorisation-code flow or the token exchange in §3.

maturad does the same for its own API. `GET /.well-known/oauth-protected-resource` names the realm, and maturad's
401 answers point to it. An agent asks for `audience=<MATURA_AUDIENCE>` (default `matura-api`) to call maturad. On
maturad's API, agents act as tenant members and never as admins or operators.

## 6. Not built yet

- Consent screens and per-tool scopes.
- Client ID Metadata Documents and dynamic registration for MCP clients outside the installation.
- Agent grants issued by a customer's identity provider.
- SCIM provisioning of agents.
- OpenFGA relations.
- Step-up authentication.
- Human-approval events mapped to EU AI Act articles 12, 14 and 26.
- Agents in the customer portal.
