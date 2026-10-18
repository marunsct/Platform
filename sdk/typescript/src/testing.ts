/** A fake Matura issuer for tests: mint tokens for any tenant, roles and permissions without Keycloak. */

import { generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from "node:crypto";

import { sign } from "./signatures.js";
import type { Jwk, JwkSet } from "./tokens.js";

export interface TokenOptions {
  userId?: string;
  tenantId?: string;
  /** Tenant slug (default: the first 8 characters of `tenantId`). */
  tenant?: string;
  workspaceId?: string;
  tenantRoles?: string[];
  roles?: string[];
  perms?: string[];
  email?: string;
  name?: string;
  /** Lifetime in seconds (default 300); negative for an expired token. */
  ttl?: number;
  audience?: string | string[];
  /** Issued-at in Unix seconds (default now). */
  now?: number;
  /** Extra or overriding claims. */
  extra?: Record<string, unknown>;
}

/** Signs tokens shaped like Matura's (contract §2). Pass `issuer.jwks` to the {@link Verifier}. */
export class FakeIssuer {
  readonly issuer: string;
  readonly audience: string;
  readonly kid: string;
  readonly jwks: JwkSet;
  private readonly key: KeyObject;

  constructor(opts: { issuer?: string; audience?: string } = {}) {
    this.issuer = opts.issuer ?? "https://matura.test/realms/matura";
    this.audience = opts.audience ?? "app";
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.key = privateKey;
    this.kid = randomUUID().replace(/-/g, "").slice(0, 16);
    const pub = publicKey.export({ format: "jwk" }) as Jwk;
    this.jwks = { keys: [{ ...pub, kid: this.kid, use: "sig", alg: "RS256" }] };
  }

  /** Sign arbitrary claims with this issuer's key (RS256). */
  signClaims(claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
    const h = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: this.kid, ...header })).toString("base64url");
    const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const s = cryptoSign("sha256", Buffer.from(`${h}.${p}`), this.key).toString("base64url");
    return `${h}.${p}.${s}`;
  }

  /** A Matura-shaped access token (same defaults as the Python SDK's `FakeIssuer.token`). */
  token(opts: TokenOptions = {}): string {
    const now = Math.trunc(opts.now ?? Date.now() / 1000);
    const sub = opts.userId ?? randomUUID();
    const aud = opts.audience ?? this.audience;
    const claims: Record<string, unknown> = {
      iss: this.issuer, aud, sub, iat: now, exp: now + (opts.ttl ?? 300),
      email: opts.email ?? `${sub.slice(0, 8)}@example.test`, email_verified: true, name: opts.name ?? "Test User",
      troles: opts.tenantRoles?.length ? opts.tenantRoles : ["member"], roles: opts.roles ?? [], perms: opts.perms ?? [],
      ver: { u: 1, m: 1, t: 1 }, azp: Array.isArray(aud) ? aud[0] : aud,
    };
    if (opts.tenantId) {
      Object.assign(claims, { tid: opts.tenantId, tenant: opts.tenant ?? opts.tenantId.slice(0, 8), pmode: "shared" });
    }
    if (opts.workspaceId) claims["wid"] = opts.workspaceId;
    Object.assign(claims, opts.extra ?? {});
    return this.signClaims(claims);
  }
}

/** Body and headers of a webhook as Matura sends it, for testing a receiver. */
export function signedEvent(
  secret: string | Uint8Array,
  event: Record<string, unknown>,
  timestamp?: number,
): { body: string; headers: Record<string, string> } {
  const body = JSON.stringify(event);
  return {
    body,
    headers: {
      "Matura-Signature": sign(secret, body, timestamp),
      "Matura-Event-Id": typeof event["id"] === "string" ? event["id"] : "",
      "Content-Type": "application/cloudevents+json",
    },
  };
}
