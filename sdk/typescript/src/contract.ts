/**
 * The `matura_*` contract tables and the version rule that keeps them current (contract §3, §5).
 *
 * Every change, from a webhook, the change feed, a snapshot or a token, goes through {@link Contract.apply}, which
 * keeps a row only when its `version` is newer than the stored one. Order and duplicates therefore do not matter.
 *
 * The database is abstracted as an {@link Executor} with positional placeholders (`$1, $2…` for PostgreSQL, `?` for
 * SQLite). The caller owns the transaction: run `apply` inside one, so the inbox row, the upserts and the hooks commit
 * together.
 */

import type { Principal } from "./principal.js";
import { POSTGRES_SHARED_RLS_SQL, POSTGRES_SQL, SQLITE_SQL } from "./sql.js";

export const CONTRACT_VERSION = "matura.contract.v1";

export type Dialect = "postgresql" | "sqlite";

/** What a query returns. `rows` is needed only for reads ({@link Contract.cursor}). node-postgres fits as is. */
export interface QueryResult {
  rowCount: number | null;
  rows?: Record<string, unknown>[];
}

/** A database connection (inside a transaction) that runs one statement with positional parameters. */
export interface Executor {
  query(sql: string, params: unknown[]): Promise<QueryResult>;
}

/** One SQL statement with its positional parameters. */
export interface Statement {
  sql: string;
  params: unknown[];
}

/** A CloudEvents envelope as Matura sends it (contract §5). */
export interface MaturaEvent {
  id?: string;
  type?: string;
  data?: { object?: string; version?: number | string; [k: string]: unknown } | null;
  [k: string]: unknown;
}

/** The event lacks a field the contract needs (answer 400; nothing was written). */
export class InvalidEvent extends Error {
  readonly status = 400;
  constructor(message: string) {
    super(message);
    this.name = "InvalidEvent";
  }
}

export type Hook = (db: Executor, event: MaturaEvent) => unknown | Promise<unknown>;

function stripComments(sql: string): string {
  return sql
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("--"))
    .join("\n");
}

/** The contract DDL as separate statements. `rls` adds the shared-mode policies (PostgreSQL only). */
export function ddl(dialect: Dialect, opts: { rls?: boolean } = {}): string[] {
  let sql: string;
  if (dialect === "postgresql") sql = stripComments(POSTGRES_SQL) + (opts.rls ? stripComments(POSTGRES_SHARED_RLS_SQL) : "");
  else if (dialect === "sqlite") sql = stripComments(SQLITE_SQL);
  else throw new Error(`contract tables for ${String(dialect)} ship in docs/contract/sql; use postgresql or sqlite here`);
  return sql
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

type Params = Record<string, unknown>;

/** Once a placement is applied, data_mode is the placement's (it has its own version), not the tenant's default. */
const KEEP_PLACED_MODE = { data_mode: "CASE WHEN t.placement_version > 0 THEN t.data_mode ELSE excluded.data_mode END" };

/** Turn `:name` placeholders into the dialect's positional ones. */
function compile(pg: boolean, sql: string, named: Params): Statement {
  const params: unknown[] = [];
  const out = sql.replace(/(?<![:\w]):([a-z_][a-z0-9_]*)/g, (_m, name: string) => {
    if (!(name in named)) throw new Error(`no parameter ${name}`);
    params.push(named[name]);
    return pg ? `$${params.length}` : "?";
  });
  return { sql: out, params };
}

class DialectValues {
  constructor(readonly pg: boolean) {}

  id(v: unknown): string | null {
    if (v === undefined || v === null || v === "") return null;
    return String(v);
  }

  ts(v: unknown): string {
    if (v === undefined || v === null) return new Date().toISOString();
    const d = v instanceof Date ? v : new Date(String(v));
    if (Number.isNaN(d.getTime())) throw new InvalidEvent(`not a timestamp: ${String(v)}`);
    return d.toISOString();
  }

  arr(v: unknown): unknown {
    const list = Array.isArray(v) ? v.map(String) : [];
    return this.pg ? list : JSON.stringify(list);
  }

  bool(v: unknown): boolean | number {
    const b = Boolean(v);
    return this.pg ? b : b ? 1 : 0;
  }
}

function req(p: Record<string, unknown>, key: string, obj: string): unknown {
  const v = p[key];
  if (v === undefined || v === null) throw new InvalidEvent(`the ${obj} in this event has no ${key}`);
  return v;
}

function opt(v: unknown): unknown {
  return v === undefined ? null : v;
}

/**
 * Applies Matura changes to the contract tables, and runs the app's hooks in the same transaction.
 *
 * `on(objectOrType, hook)` registers a hook for an object (`"membership"`), an exact event type
 * (`"matura.tenant.deleting"`) or every event (`"*"`); hooks receive `(db, event)`.
 */
export class Contract {
  readonly dialect: Dialect;
  private readonly d: DialectValues;
  private readonly hooks = new Map<string, Hook[]>();

  constructor(dialect: Dialect = "postgresql") {
    if (dialect !== "postgresql" && dialect !== "sqlite") throw new Error(`unsupported dialect ${String(dialect)}`);
    this.dialect = dialect;
    this.d = new DialectValues(dialect === "postgresql");
  }

  on(key: string, hook: Hook): Hook {
    const list = this.hooks.get(key) ?? [];
    list.push(hook);
    this.hooks.set(key, list);
    return hook;
  }

  private q(sql: string, named: Params): Statement {
    return compile(this.d.pg, sql, named);
  }

  private upsert(table: string, key: string[], cols: Params, setsOverride: Record<string, string> = {}): Statement {
    const names = Object.keys(cols);
    const sets = names.filter((c) => !key.includes(c)).map((c) => `${c} = ${setsOverride[c] ?? `excluded.${c}`}`).join(", ");
    return this.q(
      `INSERT INTO ${table} AS t (${names.join(", ")}) VALUES (${names.map((c) => ":" + c).join(", ")}) ` +
        `ON CONFLICT (${key.join(", ")}) DO UPDATE SET ${sets} WHERE t.version < excluded.version`,
      cols,
    );
  }

  private placeholder(table: string, cols: Params, key: string): Statement {
    const names = Object.keys(cols);
    return this.q(
      `INSERT INTO ${table} (${names.join(", ")}) VALUES (${names.map((c) => ":" + c).join(", ")}) ` +
        `ON CONFLICT (${key}) DO NOTHING`,
      cols,
    );
  }

  private tenantStub(tid: unknown): Statement {
    const d = this.d;
    return this.placeholder("matura_tenant", {
      id: d.id(tid), slug: String(tid), name: String(tid), kind: "company", status: "active", plan: null,
      data_mode: "shared", version: 0, updated_at: d.ts(null),
    }, "id");
  }

  private userStub(uid: unknown): Statement {
    const d = this.d;
    return this.placeholder("matura_user", {
      id: d.id(uid), email: null, email_verified: d.bool(false), display_name: null, locale: null, kind: "human",
      status: "active", version: 0, updated_at: d.ts(null),
    }, "id");
  }

  /** The SQL that applies one event (CloudEvents envelope as Matura sends it). Throws {@link InvalidEvent}. */
  statements(event: MaturaEvent): Statement[] {
    const d = this.d;
    const data = (event.data && typeof event.data === "object" ? event.data : {}) as Record<string, unknown>;
    const obj = typeof data["object"] === "string" ? data["object"] : "";
    const version = Math.trunc(Number(data["version"] || 0)) || 0;
    const raw = obj ? data[obj] : undefined;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
    const p = raw as Record<string, unknown>;
    const typ = typeof event.type === "string" ? event.type : "";
    const r = (k: string) => req(p, k, obj);

    switch (obj) {
      case "tenant":
        return [this.upsert("matura_tenant", ["id"], {
          id: d.id(r("id")), slug: r("slug"), name: r("name"), kind: p["kind"] ?? "company", status: r("status"),
          plan: opt(p["plan"]), data_mode: p["data_mode"] || p["data_mode_default"] || "shared",
          version, updated_at: d.ts(p["updated_at"]),
        }, KEEP_PLACED_MODE)];
      case "workspace":
        return [this.tenantStub(r("tenant_id")), this.upsert("matura_workspace", ["id"], {
          id: d.id(r("id")), tenant_id: d.id(p["tenant_id"]), name: r("name"), status: r("status"),
          is_default: d.bool(p["is_default"]), version, updated_at: d.ts(p["updated_at"]),
        })];
      case "user":
        return [this.upsert("matura_user", ["id"], {
          id: d.id(r("id")), email: opt(p["email"]), email_verified: d.bool(p["email_verified"]),
          display_name: opt(p["display_name"]), locale: opt(p["locale"]), kind: p["kind"] ?? "human",
          status: r("status"), version, updated_at: d.ts(p["updated_at"]),
        })];
      case "membership":
        return [this.tenantStub(r("tenant_id")), this.userStub(r("user_id")),
          this.upsert("matura_membership", ["tenant_id", "user_id"], {
            tenant_id: d.id(p["tenant_id"]), user_id: d.id(p["user_id"]), tenant_role: r("tenant_role"),
            status: r("status"), joined_at: d.ts(p["joined_at"]), version, updated_at: d.ts(p["updated_at"]),
          })];
      case "grant": {
        const stubs = [this.tenantStub(r("tenant_id"))];
        if (p["workspace_id"]) {
          stubs.push(this.placeholder("matura_workspace", {
            id: d.id(p["workspace_id"]), tenant_id: d.id(p["tenant_id"]), name: String(p["workspace_id"]),
            status: "active", is_default: d.bool(false), version: 0, updated_at: d.ts(null),
          }, "id"));
        }
        return [...stubs, this.upsert("matura_role_grant", ["id"], {
          id: d.id(r("id")), tenant_id: d.id(p["tenant_id"]), workspace_id: d.id(p["workspace_id"]),
          subject_type: r("subject_type"), subject_id: d.id(r("subject_id")), role: r("role"), status: r("status"),
          version, updated_at: d.ts(p["updated_at"]),
        })];
      }
      case "app_role": {
        const nested = p["role"];
        const role = (nested && typeof nested === "object" && !Array.isArray(nested) ? nested : p) as Record<string, unknown>;
        const name = req(role, "name", "app_role");
        const out: Statement[] = [];
        const prev = p["previous_name"];
        if (prev) {
          // renamed in Matura: grants follow, as they do there
          out.push(this.q("UPDATE matura_role_grant SET role = :new WHERE role = :old", { new: name, old: prev }));
          // the old name is gone as of this version, even if its creation arrives later
          out.push(this.upsert("matura_app_role", ["name"], {
            name: prev, description: null, permissions: d.arr([]), is_default: d.bool(false), status: "deleted",
            version, updated_at: d.ts(null),
          }));
        }
        out.push(this.upsert("matura_app_role", ["name"], {
          name, description: opt(role["description"]), permissions: d.arr(role["permissions"]),
          is_default: d.bool(role["is_default"]), status: typ.endsWith(".deleted") ? "deleted" : "active", version,
          updated_at: d.ts(null),
        }));
        return out;
      }
      case "placement": // versioned on its own: matura_tenant.placement_version
        return [this.tenantStub(r("tenant_id")), this.q(
          "UPDATE matura_tenant SET data_mode = :mode, placement_version = :version " +
            "WHERE id = :id AND placement_version < :version",
          { mode: r("mode"), version, id: d.id(r("tenant_id")) },
        )];
      default:
        return []; // tenant_app, app_manifest, ping: hooks only
    }
  }

  /**
   * Rows a verified token can create (just-in-time, contract §5). They are written only when missing, with version 0,
   * so the next event or feed read (always a higher version) fills in what a token lacks.
   */
  fromPrincipal(principal: Principal): Statement[] {
    const d = this.d;
    if (!principal.tenantId) return [];
    const now = d.ts(null);
    const tid = principal.tenantId;
    return [
      this.placeholder("matura_tenant", {
        id: d.id(tid), slug: principal.tenantSlug || tid, name: principal.tenantSlug || tid, kind: "company",
        status: "active", plan: null, data_mode: principal.placementMode || "shared", version: 0, updated_at: now,
      }, "id"),
      this.placeholder("matura_user", {
        id: d.id(principal.userId), email: principal.email || null, email_verified: d.bool(principal.emailVerified),
        display_name: principal.name, locale: null, kind: principal.isService ? "service" : "human", status: "active",
        version: 0, updated_at: now,
      }, "id"),
      this.placeholder("matura_membership", {
        tenant_id: d.id(tid), user_id: d.id(principal.userId), tenant_role: principal.tenantRoles[0] ?? "member",
        status: "active", joined_at: now, version: 0, updated_at: now,
      }, "tenant_id, user_id"),
    ];
  }

  /** Create the contract tables (idempotent) and record the contract version. */
  async create(db: Executor, opts: { rls?: boolean } = {}): Promise<void> {
    for (const stmt of ddl(this.dialect, opts)) await db.query(stmt, []);
  }

  /**
   * Apply one event and run its hooks, in the caller's transaction. Returns false for an event id already applied
   * (`matura_inbox`). Throws {@link InvalidEvent} before writing anything when the event lacks a needed field.
   */
  async apply(db: Executor, event: MaturaEvent, opts: { dedupe?: boolean } = {}): Promise<boolean> {
    const stmts = this.statements(event);
    if ((opts.dedupe ?? true) && event.id) {
      const s = this.q("INSERT INTO matura_inbox (event_id, received_at) VALUES (:id, :t) ON CONFLICT (event_id) DO NOTHING",
        { id: String(event.id), t: this.d.ts(null) });
      const res = await db.query(s.sql, s.params);
      if (!res.rowCount) return false;
    }
    for (const s of stmts) await db.query(s.sql, s.params);
    const data = event.data && typeof event.data === "object" ? event.data : {};
    const obj = typeof data.object === "string" ? data.object : "";
    const typ = typeof event.type === "string" ? event.type : "";
    for (const hook of [...(this.hooks.get(obj) ?? []), ...(this.hooks.get(typ) ?? []), ...(this.hooks.get("*") ?? [])]) {
      await hook(db, event);
    }
    return true;
  }

  /** Write the just-in-time rows for a verified token (see {@link fromPrincipal}). */
  async applyPrincipal(db: Executor, principal: Principal): Promise<void> {
    for (const s of this.fromPrincipal(principal)) await db.query(s.sql, s.params);
  }

  /** The stored change-feed cursor, or null before the first sync. Needs `rows` from the executor. */
  async cursor(db: Executor, stream = "changes"): Promise<string | null> {
    const s = this.q("SELECT cursor FROM matura_sync_cursor WHERE stream = :s", { s: stream });
    const res = await db.query(s.sql, s.params);
    const row = res.rows?.[0];
    if (!row) return null;
    const v = row["cursor"] ?? Object.values(row)[0];
    return v === undefined || v === null ? null : String(v);
  }

  async saveCursor(db: Executor, cursor: string, stream = "changes"): Promise<void> {
    const s = this.q(
      "INSERT INTO matura_sync_cursor (stream, cursor, synced_at) VALUES (:s, :c, :t) " +
        "ON CONFLICT (stream) DO UPDATE SET cursor = excluded.cursor, synced_at = excluded.synced_at",
      { s: stream, c: cursor, t: this.d.ts(null) },
    );
    await db.query(s.sql, s.params);
  }

  /** Forget processed event ids older than `days` (the feed and the version rule cover anything older). */
  async pruneInbox(db: Executor, days = 7): Promise<void> {
    const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
    const s = this.q("DELETE FROM matura_inbox WHERE received_at < :c", { c: cutoff });
    await db.query(s.sql, s.params);
  }
}
