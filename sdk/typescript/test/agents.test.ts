import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  FakeIssuer, Principal, Verifier, metadataUrl, protectedResourceMetadata, wwwAuthenticate,
} from "../src/index.js";

const AGENT = "0192b7a4-0000-7000-8000-00000000a6e7";

describe("agent identity (TS15)", () => {
  const iss = new FakeIssuer({ audience: "agentcanvas" });
  const v = new Verifier({ issuer: iss.issuer, audience: "agentcanvas", jwks: iss.jwks });

  it("reads kind and actor", async () => {
    const own = await v.verify(iss.token({ userId: AGENT, tenantId: "t1", perms: ["run.start"], extra: { kind: "agent" } }));
    assert.equal(own.kind, "agent");
    assert.equal(own.actor, null);
    assert.equal(own.isDelegated, false);
    assert.equal(own.isService, true);

    const act = { sub: AGENT, kind: "agent", client_id: "agent-3f9c2a1b7d4e" };
    const d = await v.verify(iss.token({ userId: "u1", tenantId: "t1", perms: ["workflow.read"], extra: { kind: "human", act } }));
    assert.equal(d.kind, "human");
    assert.ok(d.isDelegated);
    assert.equal(d.isService, false);
    assert.deepEqual(d.actor, { sub: AGENT, kind: "agent", clientId: "agent-3f9c2a1b7d4e" });
    assert.ok(d.has("workflow.read") && !d.has("run.start"));
    // expand keeps kind and actor
    const e = Principal.fromClaims({ sub: "u1", kind: "human", act, roles: ["viewer"], perms_ref: "matura_app_role" })
      .expand({ viewer: ["workflow.read"] });
    assert.equal(e.actor?.sub, AGENT);
    assert.equal(e.kind, "human");
  });

  it("defaults kind for older tokens", () => {
    assert.equal(Principal.fromClaims({ sub: "u", email: "a@b.c" }).kind, "human");
    assert.equal(Principal.fromClaims({ sub: "u", client_id: "worker" }).kind, "service");
    assert.equal(Principal.fromClaims({ sub: "u", kind: "robot" }).kind, "human");
    assert.deepEqual(Principal.fromClaims({ sub: "u", act: { sub: AGENT } }).actor, { sub: AGENT, kind: "agent", clientId: null });
    assert.equal(Principal.fromClaims({ sub: "u", act: "nonsense" }).actor, null);
  });

  it("builds protected-resource metadata and challenges", () => {
    assert.equal(metadataUrl("https://canvas.example.com"), "https://canvas.example.com/.well-known/oauth-protected-resource");
    assert.equal(metadataUrl("https://canvas.example.com/mcp/"), "https://canvas.example.com/.well-known/oauth-protected-resource/mcp");
    assert.throws(() => metadataUrl("/mcp"), TypeError);
    assert.deepEqual(
      protectedResourceMetadata("https://canvas.example.com/mcp", ["https://id.example.com/realms/matura"],
        { scopesSupported: ["openid"], resourceName: "AgentCanvas MCP" }),
      {
        resource: "https://canvas.example.com/mcp", authorization_servers: ["https://id.example.com/realms/matura"],
        bearer_methods_supported: ["header"], scopes_supported: ["openid"], resource_name: "AgentCanvas MCP",
      });
    assert.throws(() => protectedResourceMetadata("https://x.example", []), TypeError);
    assert.equal(wwwAuthenticate("https://canvas.example.com/mcp"),
      'Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp"');
    assert.equal(wwwAuthenticate("https://canvas.example.com/mcp", { error: "insufficient_scope", scope: 'a "b"' }),
      'Bearer resource_metadata="https://canvas.example.com/.well-known/oauth-protected-resource/mcp", ' +
      'error="insufficient_scope", scope="a \\"b\\""');
  });
});
