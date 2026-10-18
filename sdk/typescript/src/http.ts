/** Framework-agnostic HTTP helpers: authenticate a request, check permissions, receive webhooks. */

import { InvalidEvent, type Contract, type Executor } from "./contract.js";
import type { Transaction } from "./feed.js";
import type { Principal } from "./principal.js";
import { BadSignature, verify as verifySignature } from "./signatures.js";
import { bearer, type Verifier } from "./tokens.js";

/** Request headers as Node (`IncomingMessage.headers`), Express, or fetch (`Headers`) give them. */
export type HeaderBag = Headers | Record<string, string | string[] | undefined>;

/** A header value by case-insensitive name (the first one when repeated). */
export function header(headers: HeaderBag, name: string): string | undefined {
  if (typeof (headers as Headers).get === "function") return (headers as Headers).get(name) ?? undefined;
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
    if (k.toLowerCase() === want) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

/** The caller has no permission for this action (answer 403). */
export class Forbidden extends Error {
  readonly status = 403;
  constructor(message: string) {
    super(message);
    this.name = "Forbidden";
  }
}

/** Verify the request's `Authorization: Bearer …` token. Throws `InvalidToken` (401). */
export function authenticate(verifier: Verifier, headers: HeaderBag): Promise<Principal> {
  return Promise.resolve().then(() => verifier.verify(bearer(header(headers, "authorization"))));
}

/** Throw {@link Forbidden} unless the principal has every permission (`*` grants all). */
export function requirePermission(principal: Principal, ...permissions: string[]): Principal {
  const missing = permissions.filter((p) => !principal.has(p));
  if (missing.length) {
    throw new Forbidden(`you need the permission ${missing.join(", ")}; ask a tenant admin for a role that includes it`);
  }
  return principal;
}

/** Throw {@link Forbidden} unless the token is for a tenant. */
export function requireTenant(principal: Principal): Principal {
  if (!principal.tenantId) throw new Forbidden("choose an organisation first");
  return principal;
}

export interface WebhookResponse {
  status: number;
  /** Empty for 204; otherwise JSON `{"detail": "…"}`. */
  body: string;
}

export interface WebhookHandlerOptions {
  /** The endpoint's signing secret (`whsec_…`); several during a rotation. */
  secret: string | Uint8Array | (string | Uint8Array)[];
  contract: Contract;
  /** Runs each event in one transaction (recommended). */
  transaction?: Transaction;
  /** Or an executor used as is (the caller handles transactions, e.g. autocommit SQLite in tests). */
  db?: Executor;
  /** Signature tolerance in seconds (default 300). */
  toleranceSeconds?: number;
  /** Current time in Unix seconds, for tests. */
  now?: () => number;
}

function problem(status: number, detail: string): WebhookResponse {
  return { status, body: JSON.stringify({ detail }) };
}

/**
 * `POST /matura/events`: verify the signature, parse the CloudEvent and apply it (contract §10.2).
 * Answers 204 (applied, or already applied), 401 (bad signature) or 400 (not a Matura event).
 * Database errors are thrown, so the framework answers 5xx and Matura retries.
 */
export function webhookHandler(opts: WebhookHandlerOptions): (
  rawBody: string | Uint8Array,
  headers: HeaderBag,
) => Promise<WebhookResponse> {
  const run: Transaction | undefined = opts.transaction ?? (opts.db ? (fn) => fn(opts.db as Executor) : undefined);
  if (!run) throw new Error("webhookHandler needs a transaction or a db");
  const secrets = Array.isArray(opts.secret) ? opts.secret : [opts.secret];
  return async (rawBody, headers) => {
    const sig = header(headers, "matura-signature");
    let lastError: BadSignature | undefined;
    let ok = false;
    for (const s of secrets) {
      try {
        const now = opts.now?.();
        verifySignature(s, rawBody, sig, {
          ...(now !== undefined ? { now } : {}),
          ...(opts.toleranceSeconds !== undefined ? { toleranceSeconds: opts.toleranceSeconds } : {}),
        });
        ok = true;
        break;
      } catch (err) {
        if (!(err instanceof BadSignature)) throw err;
        lastError = err;
      }
    }
    if (!ok) return problem(401, lastError?.message ?? "signature does not match");
    let event: unknown;
    try {
      event = JSON.parse(typeof rawBody === "string" ? rawBody : Buffer.from(rawBody).toString("utf8"));
    } catch {
      return problem(400, "body is not JSON");
    }
    if (!event || typeof event !== "object" || Array.isArray(event)) return problem(400, "body is not a CloudEvent");
    try {
      await run((db) => opts.contract.apply(db, event as Record<string, unknown>));
    } catch (err) {
      if (err instanceof InvalidEvent) return problem(400, err.message);
      throw err;
    }
    return { status: 204, body: "" };
  };
}
