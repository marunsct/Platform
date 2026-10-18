/** Access-token verification against the Matura realm's signing keys (contract §2, level 1). */

import { constants, createPublicKey, verify as cryptoVerify, type JsonWebKey, type KeyObject } from "node:crypto";

import { Principal, type Claims } from "./principal.js";
import type { Revocations } from "./revocations.js";

/** Signature algorithms Matura tokens may use. `none` and HMAC (`HS*`) are always refused. */
export const ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384"] as const;
export type Algorithm = (typeof ALGORITHMS)[number];

/** The token is missing, malformed, expired, for another audience or signed by an unknown key (answer 401). */
export class InvalidToken extends Error {
  readonly status = 401;
  constructor(message: string) {
    super(message);
    this.name = "InvalidToken";
  }
}

export interface Jwk extends JsonWebKey {
  kid?: string;
  alg?: string;
  use?: string;
}

export interface JwkSet {
  keys: Jwk[];
}

export interface VerifierOptions {
  /** `https://<matura-host>/realms/matura`; a trailing slash is ignored. */
  issuer: string;
  /** The app's client id. */
  audience: string;
  /** Defaults to `${issuer}/protocol/openid-connect/certs`. */
  jwksUrl?: string;
  /** A static JWK Set (no network), for tests with {@link FakeIssuer} or pinned keys. */
  jwks?: JwkSet;
  /** Clock skew allowed on `exp` and `nbf`, in seconds (default 30). */
  leewaySeconds?: number;
  /** How long fetched keys are reused, in seconds (default 300). */
  jwksCacheSeconds?: number;
  /** Minimum time between refetches caused by an unknown `kid`, in seconds (default 10). */
  jwksRefetchMinSeconds?: number;
  /** Current time in Unix seconds, for tests. */
  now?: () => number;
  /** `fetch` implementation (default: the global one). */
  fetch?: typeof fetch;
  /** Revocations checked after the signature and claims: a revoked token fails like an invalid one. */
  revocations?: Revocations;
}

const HASH: Record<Algorithm, string> = {
  RS256: "sha256", RS384: "sha384", RS512: "sha512", PS256: "sha256", ES256: "sha256", ES384: "sha384",
};
const CURVE: Partial<Record<Algorithm, string>> = { ES256: "P-256", ES384: "P-384" };
const EC_SIG_BYTES: Partial<Record<Algorithm, number>> = { ES256: 64, ES384: 96 };

function b64urlJson(part: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]*$/.test(part)) throw new InvalidToken("malformed token");
  let v: unknown;
  try {
    v = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    throw new InvalidToken("malformed token");
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new InvalidToken("malformed token");
  return v as Record<string, unknown>;
}

function isAlgorithm(a: unknown): a is Algorithm {
  return typeof a === "string" && (ALGORITHMS as readonly string[]).includes(a);
}

function keyFits(jwk: Jwk, alg: Algorithm): boolean {
  if (jwk.use && jwk.use !== "sig") return false;
  if (jwk.alg && jwk.alg !== alg) return false;
  if (alg.startsWith("ES")) return jwk.kty === "EC" && jwk.crv === CURVE[alg];
  return jwk.kty === "RSA";
}

function isNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

/**
 * Verifies Matura access tokens: signature (JWKS, cached), issuer, audience (the app's client id), expiry.
 *
 * Keys come from the realm's JWKS endpoint, cached for `jwksCacheSeconds`; a token with an unknown `kid` triggers one
 * refetch (at most every `jwksRefetchMinSeconds`), so key rotation works without a restart.
 */
export class Verifier {
  readonly issuer: string;
  readonly audience: string;
  readonly jwksUrl: string;
  readonly leewaySeconds: number;
  private readonly cacheSeconds: number;
  private readonly refetchMinSeconds: number;
  private readonly clock: () => number;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly isStatic: boolean;
  private readonly revocations: Revocations | undefined;
  private keys: Jwk[] = [];
  private fetchedAt = -Infinity;
  private inflight: Promise<void> | null = null;
  private readonly keyObjects = new WeakMap<Jwk, KeyObject>();

  constructor(opts: VerifierOptions) {
    this.issuer = opts.issuer.replace(/\/+$/, "");
    this.audience = opts.audience;
    this.jwksUrl = opts.jwksUrl ?? `${this.issuer}/protocol/openid-connect/certs`;
    this.leewaySeconds = opts.leewaySeconds ?? 30;
    this.cacheSeconds = opts.jwksCacheSeconds ?? 300;
    this.refetchMinSeconds = opts.jwksRefetchMinSeconds ?? 10;
    this.clock = opts.now ?? (() => Date.now() / 1000);
    this.fetchImpl = opts.fetch;
    this.isStatic = opts.jwks !== undefined;
    this.revocations = opts.revocations;
    if (opts.jwks) this.keys = [...(opts.jwks.keys ?? [])];
  }

  /** Verify a token and return its {@link Principal}; throws {@link InvalidToken}. */
  async verify(token: string): Promise<Principal> {
    if (typeof token !== "string") throw new InvalidToken("malformed token");
    const parts = token.split(".");
    if (parts.length !== 3) throw new InvalidToken("malformed token");
    const [h, p, s] = parts as [string, string, string];
    const header = b64urlJson(h);
    const alg = header["alg"];
    if (!isAlgorithm(alg)) throw new InvalidToken(`invalid token: the algorithm ${String(alg)} is not allowed`);
    const kid = typeof header["kid"] === "string" ? header["kid"] : undefined;
    const claims = b64urlJson(p);
    if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new InvalidToken("malformed token");
    const sig = Buffer.from(s, "base64url");

    const key = await this.key(kid, alg);
    if (!this.signatureOk(alg, key, Buffer.from(`${h}.${p}`, "ascii"), sig)) {
      throw new InvalidToken("invalid token: signature verification failed");
    }
    this.checkClaims(claims);
    if (this.revocations?.revoked(claims)) throw new InvalidToken("token revoked");
    return Principal.fromClaims(claims as Claims);
  }

  private signatureOk(alg: Algorithm, key: KeyObject, data: Buffer, sig: Buffer): boolean {
    try {
      if (alg.startsWith("ES")) {
        if (sig.length !== EC_SIG_BYTES[alg]) return false;
        return cryptoVerify(HASH[alg], data, { key, dsaEncoding: "ieee-p1363" }, sig);
      }
      if (alg.startsWith("PS")) {
        return cryptoVerify(HASH[alg], data, {
          key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        }, sig);
      }
      return cryptoVerify(HASH[alg], data, key, sig);
    } catch {
      return false;
    }
  }

  private checkClaims(c: Record<string, unknown>): void {
    for (const name of ["exp", "iss", "sub", "aud"]) {
      if (c[name] === undefined || c[name] === null) {
        throw new InvalidToken(`invalid token: Token is missing the "${name}" claim`);
      }
    }
    const now = this.clock();
    const exp = c["exp"];
    if (!isNumber(exp)) throw new InvalidToken("invalid token: exp must be a number");
    if (exp <= now - this.leewaySeconds) throw new InvalidToken("token expired");
    const nbf = c["nbf"];
    if (nbf !== undefined) {
      if (!isNumber(nbf)) throw new InvalidToken("invalid token: nbf must be a number");
      if (nbf > now + this.leewaySeconds) throw new InvalidToken("invalid token: the token is not yet valid (nbf)");
    }
    const iat = c["iat"];
    if (iat !== undefined && !isNumber(iat)) throw new InvalidToken("invalid token: iat must be a number");
    if (c["iss"] !== this.issuer) throw new InvalidToken("invalid token: invalid issuer");
    const aud = c["aud"];
    const auds = Array.isArray(aud) ? aud : [aud];
    if (!auds.every((a) => typeof a === "string") || !auds.includes(this.audience)) {
      throw new InvalidToken("invalid token: audience doesn't match");
    }
    if (typeof c["sub"] !== "string" || c["sub"] === "") throw new InvalidToken("invalid token: sub must be a string");
  }

  private find(kid: string | undefined, alg: Algorithm): Jwk | undefined {
    return this.keys.find((k) => (kid === undefined || k.kid === kid) && keyFits(k, alg));
  }

  private async key(kid: string | undefined, alg: Algorithm): Promise<KeyObject> {
    let jwk: Jwk | undefined;
    if (this.isStatic) {
      jwk = this.find(kid, alg);
    } else {
      const now = this.clock();
      if (now - this.fetchedAt > this.cacheSeconds) await this.refreshKeepingOld();
      jwk = this.find(kid, alg);
      // an unknown kid usually means the realm rotated its keys: refetch once, but not more than every few seconds
      if (!jwk && this.clock() - this.fetchedAt >= this.refetchMinSeconds) {
        await this.refreshKeepingOld();
        jwk = this.find(kid, alg);
      }
    }
    if (!jwk) throw new InvalidToken("token signed with an unknown key");
    let ko = this.keyObjects.get(jwk);
    if (!ko) {
      try {
        ko = createPublicKey({ key: jwk, format: "jwk" });
      } catch {
        throw new InvalidToken("token signed with an unusable key");
      }
      this.keyObjects.set(jwk, ko);
    }
    return ko;
  }

  /** Refetch the keys; when that fails, keep using the ones already known (fail only when there are none). */
  private async refreshKeepingOld(): Promise<void> {
    try {
      await this.refresh();
    } catch (err) {
      if (this.keys.length === 0) throw err;
    }
  }

  private refresh(): Promise<void> {
    if (!this.inflight) {
      this.inflight = this.fetchJwks().finally(() => {
        this.inflight = null;
      });
    }
    return this.inflight;
  }

  private async fetchJwks(): Promise<void> {
    const f = this.fetchImpl ?? globalThis.fetch;
    let keys: unknown;
    try {
      const r = await f(this.jwksUrl, { headers: { accept: "application/json" } });
      if (!r.ok) throw new Error(`HTTP ${r.status} from ${this.jwksUrl}`);
      keys = ((await r.json()) as { keys?: unknown } | null)?.keys;
      if (!Array.isArray(keys)) throw new Error("the JWKS has no keys");
    } catch (err) {
      // keep the old keys (if any) and try again after the minimum interval
      this.fetchedAt = Math.max(this.fetchedAt, this.clock() - this.cacheSeconds + this.refetchMinSeconds);
      throw new InvalidToken(`cannot find the token's signing key: ${(err as Error).message}`);
    }
    this.keys = (keys as unknown[]).filter((k): k is Jwk => !!k && typeof k === "object");
    this.fetchedAt = this.clock();
  }
}

/** The token of an `Authorization: Bearer …` header. */
export function bearer(authorization: string | null | undefined): string {
  if (!authorization) throw new InvalidToken("sign in: send Authorization: Bearer <token>");
  const i = authorization.indexOf(" ");
  const scheme = i < 0 ? authorization : authorization.slice(0, i);
  const token = i < 0 ? "" : authorization.slice(i + 1).trim();
  if (scheme.toLowerCase() !== "bearer" || !token) throw new InvalidToken("expected Authorization: Bearer <token>");
  return token;
}
