/** Reading the app's change feed and snapshots from maturad (contract §7, level 2), and data placement (level 3). */

import type { Contract, Executor, MaturaEvent } from "./contract.js";
import type { Revocation, Revocations } from "./revocations.js";

/** The stored cursor is older than the feed keeps (30 days): take a snapshot ({@link Sync.bootstrap}). */
export class CursorExpired extends Error {
  readonly status = 410;
  constructor(message: string) {
    super(message);
    this.name = "CursorExpired";
  }
}

/** maturad answered with an error status (other than 410 on the change feed). */
export class MaturaAPIError extends Error {
  constructor(readonly status: number, readonly body: unknown, message: string) {
    super(message);
    this.name = "MaturaAPIError";
  }
}

export interface ChangesPage {
  items: MaturaEvent[];
  next_cursor: string;
  has_more: boolean;
}

export interface Snapshot {
  cursor: string;
  tenant?: Record<string, unknown> | null;
  workspaces?: Record<string, unknown>[];
  users?: Record<string, unknown>[];
  memberships?: Record<string, unknown>[];
  grants?: Record<string, unknown>[];
  placement?: Record<string, unknown> | null;
  roles?: Record<string, unknown>[];
  tenants?: string[] | null;
  [k: string]: unknown;
}

/** A tenant's placement: mode, manager, state (requested, provisioned, ready, retiring, deleted) and more. */
export type Placement = Record<string, unknown>;

/** Connection for platform-managed storage: host, port, database, user, password, search_path, expires_at. */
export type Credentials = Record<string, unknown>;

export interface StorageRegistration {
  locationLabel: string;
  databaseName?: string;
  schemaName?: string;
}

export interface MaturaAPIOptions {
  /** maturad's base URL, e.g. `https://id.example.com`. */
  baseUrl: string;
  /** The app's client id and secret (HTTP Basic). */
  clientId: string;
  clientSecret: string;
  /** Per-request timeout in milliseconds (default 10000). */
  timeoutMs?: number;
  /** `fetch` implementation (default: the global one). */
  fetch?: typeof fetch;
}

/** maturad's app endpoints, authenticated with the app's client id and secret (HTTP Basic). */
export class MaturaAPI {
  readonly baseUrl: string;
  private readonly auth: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch | undefined;

  constructor(opts: MaturaAPIOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.auth = "Basic " + Buffer.from(`${opts.clientId}:${opts.clientSecret}`, "utf8").toString("base64");
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.fetchImpl = opts.fetch;
  }

  private async request<T>(method: string, path: string, opts: { query?: Record<string, string>; body?: unknown; gone?: boolean } = {}): Promise<T> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, v);
    const headers: Record<string, string> = { authorization: this.auth, accept: "application/json" };
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    const f = this.fetchImpl ?? globalThis.fetch;
    const init: RequestInit = { method, headers, signal: AbortSignal.timeout(this.timeoutMs) };
    if (body !== undefined) init.body = body;
    const r = await f(url, init);
    const text = await r.text();
    let json: unknown = undefined;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      json = text;
    }
    const detail = (json && typeof json === "object" && "detail" in json ? String((json as { detail: unknown }).detail) : "") || text;
    if (r.status === 410 && opts.gone) throw new CursorExpired(detail || "cursor expired");
    if (!r.ok) throw new MaturaAPIError(r.status, json, `${method} ${url.pathname}: HTTP ${r.status}${detail ? `: ${detail}` : ""}`);
    return json as T;
  }

  private static seg(v: string): string {
    return encodeURIComponent(v);
  }

  private placementPath(app: string, tenantId: string): string {
    return `/v1/apps/${MaturaAPI.seg(app)}/placements/${MaturaAPI.seg(tenantId)}`;
  }

  /** Changes after `after` (an opaque cursor from `next_cursor`), in commit order. Throws {@link CursorExpired}. */
  changes(app: string, after?: string | null, limit = 500): Promise<ChangesPage> {
    const query: Record<string, string> = { limit: String(limit) };
    if (after) query["cursor"] = after;
    return this.request("GET", `/v1/apps/${MaturaAPI.seg(app)}/changes`, { query, gone: true });
  }

  /** Without `tenant`: the index (cursor, tenants that enabled the app, roles). With it: that tenant's state. */
  /** Recent token revocations for the app (technical specification §21). */
  revocations(app: string): Promise<{ items: Revocation[]; window_seconds?: number }> {
    return this.request("GET", `/v1/apps/${MaturaAPI.seg(app)}/revocations`);
  }

  snapshot(app: string, tenant?: string | null): Promise<Snapshot> {
    return this.request("GET", `/v1/apps/${MaturaAPI.seg(app)}/snapshot`, tenant ? { query: { tenant } } : {});
  }

  // --- data placement (technical specification §7, level 3) ---

  /** Where the tenant's data lives: mode, manager, state (requested, provisioned, ready, retiring, deleted). */
  placement(app: string, tenantId: string): Promise<Placement> {
    return this.request("GET", this.placementPath(app, tenantId));
  }

  /** Record storage the app created itself (manager `app`); the placement becomes `provisioned`. */
  registerPlacement(app: string, tenantId: string, storage: StorageRegistration): Promise<Placement> {
    const body: Record<string, string> = { location_label: storage.locationLabel };
    if (storage.databaseName) body["database_name"] = storage.databaseName;
    if (storage.schemaName) body["schema_name"] = storage.schemaName;
    return this.request("PUT", this.placementPath(app, tenantId), { body });
  }

  /**
   * Connection for platform-managed storage. `migrate` returns the role that owns the tables (different from the
   * runtime role in shared mode). Keep it in memory only and ask again after `expires_at`.
   */
  credentials(app: string, tenantId: string, purpose: "runtime" | "migrate" = "runtime"): Promise<Credentials> {
    return this.request("POST", this.placementPath(app, tenantId) + "/credentials", { body: { purpose } });
  }

  /** The app migrated the tenant's storage and serves it. */
  placementReady(app: string, tenantId: string): Promise<Placement> {
    return this.request("POST", this.placementPath(app, tenantId) + ":ready");
  }

  /** The app deleted a retiring tenant's data; Matura then drops platform-managed storage. */
  placementDeleted(app: string, tenantId: string): Promise<Placement> {
    return this.request("POST", this.placementPath(app, tenantId) + ":deleted");
  }

  // --- fine-grained permissions (technical specification §18); maturad answers 501 without OpenFGA ---

  private tenantPath(app: string, tenantId: string): string {
    return `/v1/apps/${MaturaAPI.seg(app)}/tenants/${MaturaAPI.seg(tenantId)}`;
  }

  /** Add and remove tuples in the tenant, all or nothing (at most 100 together). Repeating either is harmless. */
  writeRelations(app: string, tenantId: string, change: { writes?: RelationTuple[]; deletes?: RelationTuple[] }): Promise<{ written: number; deleted: number }> {
    return this.request("POST", this.tenantPath(app, tenantId) + "/relations",
      { body: { writes: change.writes ?? [], deletes: change.deletes ?? [] } });
  }

  /** Whether `user` has `relation` on `object` in the tenant. */
  async check(app: string, tenantId: string, user: string, relation: string, object: string, opts?: CheckOptions): Promise<boolean> {
    const r = await this.request<{ allowed: boolean }>("POST", this.tenantPath(app, tenantId) + ":check",
      { body: permissionQuery({ user, relation, object }, opts) });
    return r.allowed;
  }

  /** Up to 50 checks, answered in order. */
  async batchCheck(app: string, tenantId: string, checks: RelationTuple[], opts?: CheckOptions): Promise<CheckResult[]> {
    const r = await this.request<{ results: CheckResult[] }>("POST", this.tenantPath(app, tenantId) + ":batch-check",
      { body: permissionQuery({ checks }, opts) });
    return r.results;
  }

  /** The objects (`type:id`) of `type` on which `user` has `relation` in the tenant. */
  async listObjects(app: string, tenantId: string, user: string, relation: string, type: string, opts?: CheckOptions): Promise<string[]> {
    const r = await this.request<{ objects: string[] }>("POST", this.tenantPath(app, tenantId) + ":list-objects",
      { body: permissionQuery({ user, relation, type }, opts) });
    return r.objects;
  }
}

/**
 * A relationship: `user` has `relation` on `object`. Objects are `type:id` of a type in the app's authorization model;
 * users are `user:<id>`, `type:id#relation` (for example `role:editor#assignee`) or `type:*`.
 */
export interface RelationTuple {
  user: string;
  relation: string;
  object: string;
}

export interface CheckOptions {
  /** Tuples that count for this request only. */
  contextual?: RelationTuple[];
  /** Skip OpenFGA's cache, to read a tuple written just before. */
  fresh?: boolean;
}

export interface CheckResult {
  allowed: boolean;
  /** Set when this check could not be evaluated. */
  error?: string;
}

function permissionQuery(body: Record<string, unknown>, opts: CheckOptions = {}): Record<string, unknown> {
  if (opts.contextual?.length) body["contextual_tuples"] = opts.contextual;
  if (opts.fresh) body["consistency"] = "higher";
  return body;
}

/** Turn a snapshot into events the contract applies with the same version rule (no event ids: not de-duplicated). */
export function snapshotEvents(snap: Snapshot): MaturaEvent[] {
  const ev = (obj: string, typ: string, payload: Record<string, unknown>): MaturaEvent => ({
    type: `matura.${typ}`,
    data: { object: obj, version: (payload["version"] as number | undefined) ?? 0, [obj]: payload },
  });
  const out: MaturaEvent[] = (snap.roles ?? []).map((r) => ev("app_role", "app.role.updated", r));
  if (snap.tenant) out.push(ev("tenant", "tenant.updated", snap.tenant));
  for (const w of snap.workspaces ?? []) out.push(ev("workspace", "workspace.updated", w));
  for (const u of snap.users ?? []) out.push(ev("user", "user.updated", u));
  for (const m of snap.memberships ?? []) out.push(ev("membership", "membership.updated", m));
  for (const g of snap.grants ?? []) out.push(ev("grant", "grant.added", g));
  if (snap.placement) out.push(ev("placement", "placement.updated", snap.placement));
  return out;
}

/** Runs `fn` in one database transaction (commit when it resolves, roll back when it throws). */
export type Transaction = <T>(fn: (db: Executor) => Promise<T>) => Promise<T>;

export interface SyncOptions {
  api: MaturaAPI;
  /** The app's slug (its client id), as in `/v1/apps/{app}/changes`. */
  app: string;
  contract: Contract;
  transaction: Transaction;
  /** `matura_sync_cursor.stream` (default `changes`). */
  stream?: string;
  /** Page size for the change feed (default 500). */
  limit?: number;
  /** Gets each `matura.revocation.created` event the feed carries. */
  revocations?: Revocations;
}

/**
 * Keeps the contract tables current from the feed: `bootstrap` once, then `catchUp` at start-up and hourly.
 * Each page is applied and its cursor stored in one transaction, so a crash repeats at most one page.
 */
export class Sync {
  readonly api: MaturaAPI;
  readonly app: string;
  readonly contract: Contract;
  private readonly transaction: Transaction;
  private readonly stream: string;
  private readonly limit: number;
  private readonly revocations: Revocations | undefined;

  constructor(opts: SyncOptions) {
    this.api = opts.api;
    this.app = opts.app;
    this.contract = opts.contract;
    this.transaction = opts.transaction;
    this.stream = opts.stream ?? "changes";
    this.limit = opts.limit ?? 500;
    this.revocations = opts.revocations;
  }

  /** Snapshot every tenant that enabled the app, then store the cursor the first snapshot gave. */
  async bootstrap(): Promise<string> {
    const index = await this.api.snapshot(this.app);
    const cursor = String(index.cursor);
    await this.transaction(async (db) => {
      for (const e of snapshotEvents(index)) await this.contract.apply(db, e, { dedupe: false });
    });
    for (const tid of index.tenants ?? []) {
      const snap = await this.api.snapshot(this.app, tid);
      await this.transaction(async (db) => {
        for (const e of snapshotEvents(snap)) await this.contract.apply(db, e, { dedupe: false });
      });
    }
    await this.transaction((db) => this.contract.saveCursor(db, cursor, this.stream));
    return cursor;
  }

  /** Apply every change after the stored cursor. Returns how many events were new. */
  async catchUp(maxPages = 1000): Promise<number> {
    let cursor = await this.transaction((db) => this.contract.cursor(db, this.stream));
    if (cursor === null) cursor = await this.bootstrap();
    let applied = 0;
    for (let i = 0; i < maxPages; i++) {
      let page: ChangesPage;
      try {
        page = await this.api.changes(this.app, cursor, this.limit);
      } catch (err) {
        if (err instanceof CursorExpired) {
          cursor = await this.bootstrap();
          continue;
        }
        throw err;
      }
      const next = String(page.next_cursor);
      applied += await this.transaction(async (db) => {
        let n = 0;
        for (const e of page.items ?? []) {
          this.revocations?.apply(e as Record<string, unknown>);
          if (await this.contract.apply(db, e)) n++;
        }
        await this.contract.saveCursor(db, next, this.stream);
        return n;
      });
      cursor = next;
      if (!page.has_more) break;
    }
    return applied;
  }
}
