import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";

import { CursorExpired, MaturaAPI, MaturaAPIError, Sync, snapshotEvents } from "../src/index.js";
import { contractDb, stubServer, type Seen } from "./helpers.js";

const T = randomUUID();
const U = randomUUID();

function memberEvent(i: number, role: string, version: number) {
  return {
    id: `evt_${i}`, type: "matura.membership.updated",
    data: { object: "membership", version, membership: { tenant_id: T, user_id: U, tenant_role: role, status: "active" } },
  };
}

/** A stand-in for maturad's app endpoints: an index snapshot, a tenant snapshot and paged changes. */
async function fakeMaturad(pages: Record<string, unknown>, expireFirst = false) {
  let changeCalls = 0;
  return stubServer((req: Seen): [number, unknown] => {
    assert.equal(req.headers.authorization, "Basic " + Buffer.from("agentcanvas:s").toString("base64"));
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/v1/apps/agentcanvas/snapshot") {
      if (url.searchParams.get("tenant")) {
        return [200, {
          cursor: "10",
          tenant: { id: T, slug: "acme", name: "Acme", kind: "company", status: "active", data_mode_default: "shared", version: 3 },
          users: [{ id: U, email: "ana@acme.test", status: "active", version: 2 }],
          memberships: [{ tenant_id: T, user_id: U, tenant_role: "owner", status: "active", version: 4 }],
          workspaces: [], grants: [], roles: [], placement: null, tenants: null,
        }];
      }
      return [200, { cursor: "10", tenants: [T], roles: [{ name: "admin", permissions: ["*"], version: 1 }], tenant: null,
        workspaces: [], users: [], memberships: [], grants: [], placement: null }];
    }
    assert.equal(url.pathname, "/v1/apps/agentcanvas/changes");
    assert.equal(url.searchParams.get("limit"), "500");
    const cursor = url.searchParams.get("cursor") ?? "0";
    changeCalls++;
    if (expireFirst && cursor === "10" && changeCalls === 1) {
      return [410, { type: "https://matura.dev/problems/cursor-expired", status: 410, detail: "too old" }];
    }
    return [200, pages[cursor] ?? { items: [], next_cursor: cursor, has_more: false }];
  });
}

function api(url: string) {
  return new MaturaAPI({ baseUrl: url + "/", clientId: "agentcanvas", clientSecret: "s" });
}

describe("Sync", () => {
  it("bootstraps from snapshots, then applies pages", async () => {
    const pages = {
      "10": { items: [memberEvent(11, "admin", 11)], next_cursor: "11", has_more: true },
      "11": { items: [memberEvent(12, "member", 12), memberEvent(11, "admin", 11)], next_cursor: "13", has_more: false },
    };
    const srv = await fakeMaturad(pages);
    try {
      const { db, contract } = await contractDb();
      const sync = new Sync({ api: api(srv.url), app: "agentcanvas", contract, transaction: db.transaction });
      assert.equal(await sync.catchUp(), 2);
      assert.deepEqual(db.all("SELECT tenant_role FROM matura_membership"), [{ tenant_role: "member" }]);
      assert.deepEqual(db.all("SELECT cursor FROM matura_sync_cursor"), [{ cursor: "13" }]);
      assert.deepEqual(db.all("SELECT name, permissions FROM matura_app_role"), [{ name: "admin", permissions: '["*"]' }]);
      assert.deepEqual(db.all("SELECT name, version FROM matura_tenant"), [{ name: "Acme", version: 3 }]);
      // nothing new: one call from the stored cursor
      const n = srv.seen.length;
      assert.equal(await sync.catchUp(), 0);
      assert.equal(srv.seen.length, n + 1);
      assert.ok(srv.seen.at(-1)!.url.endsWith("cursor=13"));
    } finally {
      await srv.close();
    }
  });

  it("takes a new snapshot when the cursor expired", async () => {
    const srv = await fakeMaturad({}, true);
    try {
      const { db, contract } = await contractDb();
      const sync = new Sync({ api: api(srv.url), app: "agentcanvas", contract, transaction: db.transaction });
      await sync.catchUp();
      const index = srv.seen.filter((s) => s.url.includes("/snapshot") && !s.url.includes("tenant="));
      assert.equal(index.length, 2);
    } finally {
      await srv.close();
    }
  });

  it("turns snapshots into versioned events", () => {
    const evs = snapshotEvents({ cursor: "1", placement: { tenant_id: T, mode: "schema" }, grants: [{ id: "g", version: 5 }] });
    assert.deepEqual(evs.map((e) => [e.type, e.data?.version]), [["matura.grant.added", 5], ["matura.placement.updated", 0]]);
    assert.equal(evs[0]!.id, undefined);
  });
});

describe("MaturaAPI", () => {
  it("calls the placement endpoints", async () => {
    const srv = await stubServer((req) => {
      if (req.url.endsWith("/credentials")) return [200, { user: "app_t_1", password: "pw", database: "app_t_acme" }];
      if (req.url.includes("missing")) return [404, { status: 404, detail: "not found" }];
      return [200, { state: "ready" }];
    });
    try {
      const m = new MaturaAPI({ baseUrl: srv.url, clientId: "notes", clientSecret: "mts_x" });
      assert.equal((await m.placement("notes", "t1"))["state"], "ready");
      await m.registerPlacement("notes", "t1", { locationLabel: "eu-1 / db", schemaName: "t_acme" });
      assert.equal((await m.credentials("notes", "t1", "migrate"))["user"], "app_t_1");
      await m.credentials("notes", "t1");
      await m.placementReady("notes", "t1");
      await m.placementDeleted("notes", "t1");
      assert.deepEqual(srv.seen.map((s) => [s.method, s.url]), [
        ["GET", "/v1/apps/notes/placements/t1"], ["PUT", "/v1/apps/notes/placements/t1"],
        ["POST", "/v1/apps/notes/placements/t1/credentials"], ["POST", "/v1/apps/notes/placements/t1/credentials"],
        ["POST", "/v1/apps/notes/placements/t1:ready"], ["POST", "/v1/apps/notes/placements/t1:deleted"],
      ]);
      assert.deepEqual(JSON.parse(srv.seen[1]!.body), { location_label: "eu-1 / db", schema_name: "t_acme" });
      assert.deepEqual(JSON.parse(srv.seen[2]!.body), { purpose: "migrate" });
      assert.deepEqual(JSON.parse(srv.seen[3]!.body), { purpose: "runtime" });
      assert.equal(srv.seen[4]!.body, "");
      assert.equal(srv.seen[0]!.headers.authorization, "Basic " + Buffer.from("notes:mts_x").toString("base64"));

      await assert.rejects(m.placement("notes", "missing"), (err: unknown) => {
        assert.ok(err instanceof MaturaAPIError);
        assert.equal(err.status, 404);
        assert.match(err.message, /not found/);
        return true;
      });
    } finally {
      await srv.close();
    }
  });

  it("reads changes and snapshots, and maps 410 to CursorExpired", async () => {
    const srv = await stubServer((req) => {
      if (req.url.includes("cursor=old")) return [410, { detail: "cursor is older than 30 days" }];
      if (req.url.includes("/snapshot")) return [200, { cursor: "5", tenants: [] }];
      return [200, { items: [], next_cursor: "9", has_more: false }];
    });
    try {
      const m = new MaturaAPI({ baseUrl: srv.url, clientId: "notes", clientSecret: "x" });
      assert.equal((await m.changes("notes")).next_cursor, "9");
      await m.changes("notes", "4", 50);
      await m.snapshot("notes");
      await m.snapshot("notes", T);
      await assert.rejects(m.changes("notes", "old"), (err: unknown) => err instanceof CursorExpired && /30 days/.test(err.message));
      assert.deepEqual(srv.seen.map((s) => s.url), [
        "/v1/apps/notes/changes?limit=500", "/v1/apps/notes/changes?limit=50&cursor=4", "/v1/apps/notes/snapshot",
        `/v1/apps/notes/snapshot?tenant=${T}`, "/v1/apps/notes/changes?limit=500&cursor=old",
      ]);
    } finally {
      await srv.close();
    }
  });
});
