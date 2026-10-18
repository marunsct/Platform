/** Webhook signatures (contract §6, §10.2): `Matura-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">`. */

import { createHmac, timingSafeEqual } from "node:crypto";

export const TOLERANCE_SECONDS = 300;

/** The webhook is not from Matura, was changed, or is too old (answer 401 and do not apply it). */
export class BadSignature extends Error {
  readonly status = 401;
  constructor(message: string) {
    super(message);
    this.name = "BadSignature";
  }
}

export type Secret = string | Uint8Array;
export type Body = string | Uint8Array;

function mac(secret: Secret, t: string, body: Body): string {
  const h = createHmac("sha256", secret);
  h.update(`${t}.`);
  h.update(body);
  return h.digest("hex");
}

/** The `Matura-Signature` header for `body`, signed at `timestamp` (Unix seconds, default now). */
export function sign(secret: Secret, body: Body, timestamp?: number): string {
  const t = String(Math.trunc(timestamp ?? Date.now() / 1000));
  return `t=${t},v1=${mac(secret, t, body)}`;
}

export interface VerifyOptions {
  /** Current time in Unix seconds (default now). */
  now?: number;
  /** How far `t` may be from now, in seconds (default 300). */
  toleranceSeconds?: number;
}

/**
 * Throw {@link BadSignature} unless `header` signs `body` with `secret` within the tolerance.
 * During a secret rotation Matura sends several `v1=` values; any one matching is enough.
 */
export function verify(secret: Secret, body: Body, header: string | null | undefined, opts: VerifyOptions = {}): void {
  if (!header) throw new BadSignature("missing Matura-Signature");
  let t = "";
  const sigs: string[] = [];
  for (const part of header.split(",")) {
    const p = part.trim();
    const i = p.indexOf("=");
    const k = i < 0 ? p : p.slice(0, i);
    const v = i < 0 ? "" : p.slice(i + 1);
    if (k === "t") t = v;
    else if (k === "v1") sigs.push(v);
  }
  if (!/^[0-9]+$/.test(t) || sigs.length === 0) throw new BadSignature("malformed Matura-Signature");
  const now = opts.now ?? Date.now() / 1000;
  if (Math.abs(now - Number(t)) > (opts.toleranceSeconds ?? TOLERANCE_SECONDS)) {
    throw new BadSignature("signature timestamp is too old or in the future");
  }
  const want = Buffer.from(mac(secret, t, body), "utf8");
  let ok = false;
  for (const s of sigs) {
    const got = Buffer.from(s, "utf8");
    // compare every candidate, in constant time for equal lengths
    if (got.length === want.length && timingSafeEqual(got, want)) ok = true;
  }
  if (!ok) throw new BadSignature("signature does not match");
}
