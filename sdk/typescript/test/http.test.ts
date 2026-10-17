import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";

import {
  FakeIssuer, Forbidden, InvalidToken, Principal, Verifier, authenticate, requirePermission, requireTenant, sign,
  signedEvent, webhookHandler,
} from "../src/index.js";
import { contractDb } from "./helpers.js";

describe("authenticate and requirePermission", () => {
  const iss = new FakeIssuer({ audience: "agentcanvas" });
  const v = new Verifier({ issuer: iss.issuer, audience: "agentcanvas", jwks: iss.jwks });
  const t = randomUUID();

  it("checks the token and the permission", async () => {
    await assert.rejects(authenticate(v, {}), InvalidToken);
    await assert.rejects(authenticate(v, { authorization: "Basic x" }), InvalidToken);
    const reader = await authenticate(v, { Authorization: "Bearer " + iss.token({ tenantId: t, perms: ["workflow.read"] }) });
    assert.throws(() => requirePermission(reader, "workflow.write"), (err: unknown) => {
      assert.ok(err instanceof Forbidden);
      assert.equal(err.status, 403);
      assert.match(err.message, /workflow\.write/);
      return true;
    });
    const writer = await authenticate(v, new Headers({ authorization: "Bearer " + iss.token({ tenantId: t, perms: ["workflow.write"] }) }));
    assert.equal(requirePermission(writer, "workflow.write").tenantId, t);
    assert.equal(requireTenant(writer), writer);
    assert.throws(() => requireTenant(new Principal({ ...writer, tenantId: null })), Forbidden);
    const multi = await authenticate(v, { authorization: ["Bearer " + iss.token({ perms: ["*"] })] });
    requirePermission(multi, "a", "b");
  });
});

describe("webhookHandler", () => {
  const t = randomUUID();
  const event = {
    id: "evt_1", type: "matura.tenant.created",
    data: { object: "tenant", version: 3, tenant: { id: t, slug: "acme", name: "Acme", kind: "company", status: "active" } },
  };

  it("verifies, applies once, and refuses forgeries", async () => {
    const { db, contract } = await contractDb();
    const handle = webhookHandler({ secret: "whsec_1", contract, transaction: db.transaction });
    const { body, headers } = signedEvent("whsec_1", event);

    const forged = await handle(body, { ...headers, "Matura-Signature": "t=1,v1=00" });
    assert.equal(forged.status, 401);
    assert.match(JSON.parse(forged.body).detail, /too old/);
    assert.equal((await handle(body, {})).status, 401);
    assert.equal((await handle(body + " ", headers)).status, 401);

    assert.deepEqual(await handle(body, headers), { status: 204, body: "" });
    assert.deepEqual(await handle(Buffer.from(body), headers), { status: 204, body: "" }); // repeat: skipped
    assert.deepEqual(db.all("SELECT name, version FROM matura_tenant"), [{ name: "Acme", version: 3 }]);
    assert.deepEqual(db.all("SELECT event_id FROM matura_inbox"), [{ event_id: "evt_1" }]);
  });

  it("answers 400 for a body that is not a Matura event", async () => {
    const { db, contract } = await contractDb();
    const handle = webhookHandler({ secret: "s", contract, db: db.executor });
    for (const raw of ["not json", "[1]", "null"]) {
      const res = await handle(raw, { "matura-signature": sign("s", raw) });
      assert.equal(res.status, 400, raw);
    }
    const bad = { id: "evt_2", type: "matura.user.created", data: { object: "user", version: 1, user: { id: randomUUID() } } };
    const s = signedEvent("s", bad);
    const res = await handle(s.body, s.headers);
    assert.equal(res.status, 400);
    assert.match(res.body, /status/);
    assert.deepEqual(db.all("SELECT * FROM matura_inbox"), []);
  });

  it("accepts any of several secrets during a rotation, and an injected clock", async () => {
    const { db, contract } = await contractDb();
    const handle = webhookHandler({ secret: ["old", "new"], contract, transaction: db.transaction, now: () => 5000 });
    const s = signedEvent("new", event, 5100);
    assert.equal((await handle(s.body, s.headers)).status, 204);
    const stale = signedEvent("new", { ...event, id: "evt_2" }, 4000);
    assert.equal((await handle(stale.body, stale.headers)).status, 401);
  });

  it("lets database errors through, so Matura retries", async () => {
    const { contract } = await contractDb();
    const handle = webhookHandler({
      secret: "s", contract, db: { query: async () => { throw new Error("db down"); } },
    });
    const s = signedEvent("s", event);
    await assert.rejects(handle(s.body, s.headers), /db down/);
  });
});
