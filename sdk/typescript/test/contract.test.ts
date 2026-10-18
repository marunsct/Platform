import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";

import {
  CONTRACT_VERSION, Contract, InvalidEvent, POSTGRES_SHARED_RLS_SQL, POSTGRES_SQL, Principal, SQLITE_SQL, ddl,
  type MaturaEvent,
} from "../src/index.js";
import { contractDb, repoFile, type SqliteDb } from "./helpers.js";

const T = randomUUID();
const U = randomUUID();
const W = randomUUID();
const G = randomUUID();

function ev(i: number, typ: string, obj: string, version: number, payload: Record<string, unknown>): MaturaEvent {
  return { id: `evt_${i}`, type: `matura.${typ}`, data: { object: obj, version, [obj]: payload } };
}

function history(): MaturaEvent[] {
  return [
    ev(1, "user.created", "user", 1, { id: U, email: "ana@acme.test", email_verified: true, display_name: "Ana", kind: "human", status: "active" }),
    ev(2, "tenant.created", "tenant", 2, { id: T, slug: "acme", name: "Acme", kind: "company", status: "active", data_mode_default: "shared" }),
    ev(3, "workspace.created", "workspace", 3, { id: W, tenant_id: T, name: "Default", status: "active", is_default: true }),
    ev(4, "membership.added", "membership", 4, { tenant_id: T, user_id: U, tenant_role: "member", status: "active" }),
    ev(5, "app.role.created", "app_role", 5, { name: "editor", permissions: ["workflow.write"] }),
    ev(6, "grant.added", "grant", 6, { id: G, tenant_id: T, workspace_id: W, subject_type: "user", subject_id: U, role: "editor", status: "active" }),
    ev(7, "membership.updated", "membership", 7, { tenant_id: T, user_id: U, tenant_role: "admin", status: "active" }),
    ev(8, "tenant.updated", "tenant", 8, { id: T, slug: "acme", name: "Acme Corp", kind: "company", status: "active", data_mode_default: "shared" }),
    ev(9, "app.role.updated", "app_role", 9, { role: { name: "author", permissions: ["workflow.write"] }, previous_name: "editor" }),
    ev(10, "user.updated", "user", 10, { id: U, email: "ana@acme.example", email_verified: true, display_name: "Ana S", kind: "human", status: "active" }),
  ];
}

const QUERIES = [
  "SELECT name, version FROM matura_tenant",
  "SELECT tenant_role, version FROM matura_membership",
  "SELECT email, display_name FROM matura_user",
  "SELECT role, status FROM matura_role_grant",
  "SELECT name, status FROM matura_app_role ORDER BY name",
  "SELECT name FROM matura_workspace",
];

function state(db: SqliteDb): Record<string, unknown[][]> {
  return Object.fromEntries(QUERIES.map((q) => [q, db.all(q).map((r) => Object.values(r))]));
}

function shuffle<T>(list: T[], seed: number): T[] {
  let s = seed + 1;
  const rnd = () => ((s = (s * 1103515245 + 12345) % 2147483648) / 2147483648);
  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [list[i], list[j]] = [list[j]!, list[i]!];
  }
  return list;
}

describe("Contract", () => {
  it("ships the DDL from docs/contract/sql verbatim", () => {
    assert.equal(POSTGRES_SQL, repoFile("docs/contract/sql/postgres.sql"));
    assert.equal(POSTGRES_SHARED_RLS_SQL, repoFile("docs/contract/sql/postgres-shared-rls.sql"));
    assert.equal(SQLITE_SQL, repoFile("docs/contract/sql/sqlite.sql"));
    const pg = ddl("postgresql");
    assert.equal(pg.length, 12);
    assert.ok(pg.every((s) => !s.includes("--")));
    assert.equal(ddl("postgresql", { rls: true }).length, 12 + 20);
    assert.ok(ddl("postgresql", { rls: true }).at(-1)!.startsWith("CREATE POLICY tenant_isolation ON matura_user"));
    assert.equal(ddl("sqlite").length, 11);
    assert.throws(() => ddl("mysql" as "sqlite"), /docs\/contract\/sql/);
  });

  it("creates the tables and records the contract version", async () => {
    const { db, contract } = await contractDb();
    await contract.create(db.executor); // idempotent
    assert.deepEqual(db.all("SELECT version FROM matura_contract"), [{ version: CONTRACT_VERSION }]);
  });

  it("generates $n placeholders for PostgreSQL and ? for SQLite", () => {
    const e = history()[3]!;
    const pg = new Contract("postgresql").statements(e);
    const up = pg.at(-1)!;
    assert.equal(
      up.sql,
      "INSERT INTO matura_membership AS t (tenant_id, user_id, tenant_role, status, joined_at, version, updated_at) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (tenant_id, user_id) DO UPDATE SET tenant_role = excluded.tenant_role, " +
        "status = excluded.status, joined_at = excluded.joined_at, version = excluded.version, updated_at = excluded.updated_at " +
        "WHERE t.version < excluded.version",
    );
    assert.deepEqual(up.params.slice(0, 4), [T, U, "member", "active"]);
    assert.equal(up.params[5], 4);
    assert.ok(pg[0]!.sql.endsWith("ON CONFLICT (id) DO NOTHING"));
    const lite = new Contract("sqlite").statements(e).at(-1)!;
    assert.ok(lite.sql.includes("VALUES (?, ?, ?, ?, ?, ?, ?)"));
    const rename = new Contract("postgresql").statements(history()[8]!);
    assert.equal(rename[0]!.sql, "UPDATE matura_role_grant SET role = $1 WHERE role = $2");
    assert.deepEqual(rename[0]!.params, ["author", "editor"]);
    assert.deepEqual(rename[2]!.params[2], ["workflow.write"], "PostgreSQL gets a text[] array");
    assert.equal(new Contract("sqlite").statements(history()[8]!)[2]!.params[2], '["workflow.write"]');
  });

  it("does not care about order or duplicates", async () => {
    const { db, contract } = await contractDb();
    await db.transaction(async (x) => {
      for (const e of history()) await contract.apply(x, e);
    });
    const want = state(db);
    assert.deepEqual(want[QUERIES[0]!], [["Acme Corp", 8]]);
    assert.deepEqual(want[QUERIES[1]!], [["admin", 7]]);
    assert.deepEqual(want[QUERIES[3]!], [["author", "active"]]);
    assert.deepEqual(want[QUERIES[4]!], [["author", "active"], ["editor", "deleted"]]);

    for (let seed = 0; seed < 5; seed++) {
      for (const t of ["matura_role_grant", "matura_membership", "matura_workspace", "matura_user", "matura_tenant", "matura_app_role", "matura_inbox"]) {
        db.raw.exec(`DELETE FROM ${t}`);
      }
      // apply each event alone, as webhooks would
      for (const e of shuffle([...history(), ...history()], seed)) await db.transaction((x) => contract.apply(x, e));
      const got = state(db);
      for (const q of QUERIES) {
        if (q.includes("role_grant")) continue; // a grant replayed after the rename keeps its old name until the feed
        assert.deepEqual(got[q], want[q], `${seed} ${q}`);
      }
    }
  });

  it("skips repeats through the inbox and runs hooks", async () => {
    const { db, contract } = await contractDb();
    const seen: string[] = [];
    contract.on("membership", (_db, e) => void seen.push(String(e.id)));
    contract.on("matura.tenant.created", async () => void seen.push("tenant!"));
    contract.on("*", () => void seen.push("*"));
    await db.transaction(async (x) => {
      for (const e of history().slice(0, 4)) assert.equal(await contract.apply(x, e), true);
      assert.equal(await contract.apply(x, history()[3]!), false);
    });
    assert.deepEqual(seen, ["*", "tenant!", "*", "*", "evt_4", "*"]);
    assert.equal(await db.transaction((x) => contract.apply(x, history()[3]!, { dedupe: false })), true);
  });

  it("rolls back with the caller's transaction when a hook fails", async () => {
    const { db, contract } = await contractDb();
    contract.on("tenant", () => {
      throw new Error("boom");
    });
    await assert.rejects(db.transaction((x) => contract.apply(x, history()[1]!)), /boom/);
    assert.deepEqual(db.all("SELECT * FROM matura_inbox"), []);
    assert.deepEqual(db.all("SELECT * FROM matura_tenant"), []);
  });

  it("refuses an event without a needed field before writing", async () => {
    const { db, contract } = await contractDb();
    const bad = ev(1, "tenant.created", "tenant", 1, { id: T, name: "x", status: "active" });
    await assert.rejects(contract.apply(db.executor, bad), InvalidEvent);
    assert.deepEqual(db.all("SELECT * FROM matura_inbox"), []);
    // unknown objects and pings only run hooks
    assert.deepEqual(contract.statements({ id: "x", type: "matura.ping", data: { object: "ping" } }), []);
    assert.deepEqual(contract.statements({ id: "x", type: "matura.tenant_app.enabled", data: { object: "tenant_app", version: 3, tenant_app: { tenant_id: T } } }), []);
  });

  it("writes token rows only when missing, and events fill them in", async () => {
    const { db, contract } = await contractDb();
    const p = Principal.fromClaims({ sub: U, tid: T, tenant: "acme", troles: ["member"], email: "a@x" });
    await db.transaction(async (x) => {
      await contract.applyPrincipal(x, p);
      await contract.applyPrincipal(x, p); // repeats do nothing
    });
    assert.deepEqual(state(db)[QUERIES[0]!], [["acme", 0]]);
    assert.deepEqual(db.all("SELECT email, kind, email_verified FROM matura_user"), [{ email: "a@x", kind: "human", email_verified: 0 }]);
    assert.deepEqual(db.all("SELECT tenant_role, version FROM matura_membership"), [{ tenant_role: "member", version: 0 }]);
    await db.transaction((x) => contract.apply(x, history()[1]!));
    assert.deepEqual(state(db)[QUERIES[0]!], [["Acme", 2]]);
    assert.deepEqual(contract.fromPrincipal(Principal.fromClaims({ sub: U })), []);
  });

  it("keeps the cursor and prunes the inbox", async () => {
    const { db, contract } = await contractDb();
    assert.equal(await contract.cursor(db.executor), null);
    await contract.saveCursor(db.executor, "41");
    await contract.saveCursor(db.executor, "42");
    await contract.saveCursor(db.executor, "7", "changes:t1");
    assert.equal(await contract.cursor(db.executor), "42");
    assert.equal(await contract.cursor(db.executor, "changes:t1"), "7");

    await contract.apply(db.executor, history()[0]!);
    db.raw.exec("INSERT INTO matura_inbox (event_id, received_at) VALUES ('old', '2020-01-01T00:00:00.000Z')");
    await contract.pruneInbox(db.executor);
    assert.deepEqual(db.all("SELECT event_id FROM matura_inbox"), [{ event_id: "evt_1" }]);
  });
});
