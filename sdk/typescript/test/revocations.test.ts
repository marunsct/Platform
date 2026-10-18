import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FakeIssuer, InvalidToken, Revocations, Verifier } from "../src/index.js";

const iso = (s: number) => new Date(s * 1000).toISOString();
const now = () => Date.now() / 1000;

describe("Revocations", () => {
  it("stop revoked tokens before they expire", async () => {
    const iss = new FakeIssuer({ audience: "notes" });
    const revs = new Revocations();
    const v = new Verifier({ issuer: iss.issuer, audience: "notes", jwks: iss.jwks, revocations: revs });
    const old = Math.trunc(now()) - 60;
    const token = iss.token({ userId: "u1", tenantId: "t1", now: old, extra: { sid: "s1" } });
    await v.verify(token);

    assert.ok(revs.apply({ type: "matura.revocation.created", data: { object: "revocation", version: 3,
      revocation: { id: "r1", user_id: "u1", tenant_id: null, session_id: "s2", not_before: iso(now()) } } }));
    await v.verify(token); // another session

    revs.add({ id: "r2", user_id: "u1", tenant_id: "t1", not_before: iso(now()) });
    await assert.rejects(v.verify(token), (e: unknown) => e instanceof InvalidToken && /revoked/.test(e.message));
    await v.verify(iss.token({ userId: "u1", tenantId: "t2", now: old })); // another tenant
    await v.verify(iss.token({ userId: "u1", tenantId: "t1", now: Math.trunc(now()) + 2 })); // issued after

    revs.add({ id: "r3", user_id: "agent", not_before: iso(now()) });
    await assert.rejects(v.verify(iss.token({ userId: "u9", tenantId: "t1", now: old, extra: { act: { sub: "agent" } } })), InvalidToken);

    revs.add({ id: "r4", user_id: "u7", actor_id: "a2", not_before: iso(now()) });
    await assert.rejects(v.verify(iss.token({ userId: "u7", tenantId: "t1", now: old, extra: { act: { sub: "a2" } } })), InvalidToken);
    await v.verify(iss.token({ userId: "u7", tenantId: "t1", now: old }));
    await v.verify(iss.token({ userId: "u7", tenantId: "t1", now: old, extra: { act: { sub: "a3" } } }));

    revs.add({ id: "old", user_id: "x", not_before: iso(now() - 3600) });
    assert.equal(revs.size, 4);
    assert.ok(!revs.apply({ type: "matura.user.updated", data: { object: "user", user: {} } }));
  });

  it("load from the API", async () => {
    const revs = new Revocations();
    await revs.load({ revocations: async (app: string) => {
      assert.equal(app, "notes");
      return { items: [{ id: "r1", user_id: "u1", tenant_id: null, session_id: null, not_before: iso(now()) }] };
    } }, "notes");
    assert.equal(revs.size, 1);
    assert.ok(revs.revoked({ sub: "u1", iat: Math.trunc(now()) - 5 }));
  });
});
