import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { DatabaseSync } from "node:sqlite";

import { Contract, ddl, type Executor, type Transaction } from "../src/index.js";

/** docs/contract/ from build-test/test/ (compiled) */
export const REPO = new URL("../../../../", import.meta.url);

export function repoFile(path: string): string {
  return readFileSync(new URL(path, REPO), "utf8");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const VECTORS: any = JSON.parse(repoFile("docs/contract/test-vectors.json"));

/** node:sqlite wrapped as the SDK's executor, with BEGIN/COMMIT transactions. */
export class SqliteDb {
  readonly raw = new DatabaseSync(":memory:");

  readonly executor: Executor = {
    query: async (sql, params) => {
      const stmt = this.raw.prepare(sql);
      const args = params as (string | number | null)[];
      if (/^\s*select\b/i.test(sql)) {
        const rows = stmt.all(...args) as Record<string, unknown>[];
        return { rowCount: rows.length, rows };
      }
      const r = stmt.run(...args);
      return { rowCount: Number(r.changes) };
    },
  };

  readonly transaction: Transaction = async (fn) => {
    this.raw.exec("BEGIN");
    try {
      const out = await fn(this.executor);
      this.raw.exec("COMMIT");
      return out;
    } catch (err) {
      this.raw.exec("ROLLBACK");
      throw err;
    }
  };

  all(sql: string): Record<string, unknown>[] {
    return (this.raw.prepare(sql).all() as Record<string, unknown>[]).map((r) => ({ ...r }));
  }
}

export async function contractDb(): Promise<{ db: SqliteDb; contract: Contract }> {
  const db = new SqliteDb();
  for (const s of ddl("sqlite")) db.raw.exec(s);
  return { db, contract: new Contract("sqlite") };
}

export interface Seen {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body: string;
}

/** A local HTTP server; `handle` returns [status, json body]. */
export async function stubServer(
  handle: (req: Seen) => [number, unknown] | Promise<[number, unknown]>,
): Promise<{ url: string; seen: Seen[]; close: () => Promise<void> }> {
  const seen: Seen[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      const s: Seen = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString() };
      seen.push(s);
      const [status, body] = await handle(s);
      res.writeHead(status, { "content-type": "application/json" });
      res.end(body === undefined ? "" : JSON.stringify(body));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
