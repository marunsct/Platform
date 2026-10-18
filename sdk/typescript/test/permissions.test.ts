import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MaturaAPI, MaturaAPIError, type RelationTuple } from "../src/index.js";
import { stubServer, type Seen } from "./helpers.js";

/** A stand-in for maturad's permission endpoints: keeps tuples, answers direct checks. */
async function fakePermissions() {
  const tuples = new Set<string>();
  const key = (t: RelationTuple) => `${t.user}|${t.relation}|${t.object}`;
  return stubServer((req: Seen): [number, unknown] => {
    assert.equal(req.headers.authorization, "Basic " + Buffer.from("notes:s").toString("base64"));
    const body = JSON.parse(req.body || "{}");
    const path = new URL(req.url, "http://x").pathname;
    if (!path.startsWith("/v1/apps/notes/tenants/t1")) {
      return [501, { type: "https://matura.dev/problems/permissions-not-configured", status: 501, detail: "no OpenFGA" }];
    }
    if (path.endsWith("/relations")) {
      body.writes.forEach((t: RelationTuple) => tuples.add(key(t)));
      body.deletes.forEach((t: RelationTuple) => tuples.delete(key(t)));
      return [200, { written: body.writes.length, deleted: body.deletes.length }];
    }
    if (path.endsWith(":check")) return [200, { allowed: tuples.has(key(body)) }];
    if (path.endsWith(":batch-check")) {
      return [200, { results: body.checks.map((c: RelationTuple) => ({ allowed: tuples.has(key(c)) })) }];
    }
    if (path.endsWith(":list-objects")) {
      const objs = [...tuples].map((k) => k.split("|")).filter(([u, r]) => u === body.user && r === body.relation).map(([, , o]) => o);
      return [200, { objects: objs.sort() }];
    }
    return [404, {}];
  });
}

describe("permission helpers", () => {
  it("write, check, batch check, list and delete", async () => {
    const srv = await fakePermissions();
    try {
      const api = new MaturaAPI({ baseUrl: srv.url, clientId: "notes", clientSecret: "s" });
      const d1 = { user: "user:u1", relation: "editor", object: "document:d1" };
      assert.deepEqual(await api.writeRelations("notes", "t1", { writes: [d1, { ...d1, object: "document:d2" }] }),
        { written: 2, deleted: 0 });
      assert.equal(await api.check("notes", "t1", "user:u1", "editor", "document:d1", { fresh: true }), true);
      assert.equal(JSON.parse(srv.seen.at(-1)!.body).consistency, "higher");
      assert.equal(await api.check("notes", "t1", "user:u2", "editor", "document:d1"), false);
      const res = await api.batchCheck("notes", "t1", [d1, { ...d1, user: "user:u2" }],
        { contextual: [{ user: "user:u2", relation: "viewer", object: "document:d1" }] });
      assert.deepEqual(res.map((r) => r.allowed), [true, false]);
      assert.equal(JSON.parse(srv.seen.at(-1)!.body).contextual_tuples.length, 1);
      assert.deepEqual(await api.listObjects("notes", "t1", "user:u1", "editor", "document"), ["document:d1", "document:d2"]);
      await api.writeRelations("notes", "t1", { deletes: [d1] });
      assert.equal(await api.check("notes", "t1", "user:u1", "editor", "document:d1"), false);
      await assert.rejects(api.check("notes", "t2", "user:u1", "editor", "document:d1"),
        (e: unknown) => e instanceof MaturaAPIError && e.status === 501);
    } finally {
      await srv.close();
    }
  });
});
