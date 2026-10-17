/** The shared vectors (docs/contract/test-vectors.json) that every Matura SDK runs. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { BadSignature, InvalidToken, Verifier, verifySignature } from "../src/index.js";
import { contractDb, VECTORS } from "./helpers.js";

describe("signature vectors", () => {
  for (const s of VECTORS.signatures) {
    it(s.name, () => {
      let ok = true;
      try {
        verifySignature(VECTORS.secret, s.body, s.header, { now: s.now });
      } catch (err) {
        assert.ok(err instanceof BadSignature);
        ok = false;
      }
      assert.equal(ok, s.valid);
    });
  }
});

describe("token vectors", () => {
  const t = VECTORS.tokens;
  const verifier = new Verifier({ issuer: t.issuer, audience: t.audience, jwks: t.jwks, now: () => t.now });
  for (const c of t.cases) {
    it(c.name, async () => {
      if (!c.valid) {
        await assert.rejects(verifier.verify(c.token), InvalidToken);
        return;
      }
      const p = await verifier.verify(c.token);
      const want = c.principal;
      assert.equal(p.userId, want.user_id);
      assert.equal(p.tenantId, want.tenant_id);
      assert.equal(p.tenantSlug, want.tenant_slug);
      assert.equal(p.workspaceId, want.workspace_id);
      assert.deepEqual([...p.tenantRoles], want.tenant_roles);
      assert.deepEqual([...p.roles], want.roles);
      assert.deepEqual([...p.permissions], want.permissions);
      assert.equal(p.email, want.email);
      assert.equal(p.placementMode, want.placement_mode);
      for (const [perm, ok] of Object.entries(want.has)) assert.equal(p.has(perm), ok, perm);
    });
  }
});

describe("apply vectors", () => {
  it("applies the events with the version rule (node:sqlite)", async () => {
    const a = VECTORS.apply;
    const { db, contract } = await contractDb();
    const applied: boolean[] = [];
    await db.transaction(async (x) => {
      for (const e of a.events) applied.push(await contract.apply(x, e));
    });
    assert.deepEqual(applied, a.applied);
    for (const [table, want] of Object.entries(a.rows as Record<string, Record<string, unknown>[]>)) {
      const cols = Object.keys(want[0]!);
      const got = db.all(`SELECT ${cols.join(", ")} FROM ${table} ORDER BY ${cols[0]}`).map((row) => {
        if ("permissions" in row) row["permissions"] = JSON.parse(String(row["permissions"]));
        if ("is_default" in row) row["is_default"] = Boolean(row["is_default"]);
        return row;
      });
      assert.deepEqual(got, want, table);
    }
  });
});
