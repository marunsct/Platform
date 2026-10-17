import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign as cryptoSign, constants, type KeyObject } from "node:crypto";
import { describe, it } from "node:test";

import { FakeIssuer, InvalidToken, Principal, Verifier, bearer, type Jwk } from "../src/index.js";
import { stubServer } from "./helpers.js";

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

function jwt(header: Record<string, unknown>, claims: Record<string, unknown>, signer: (data: Buffer) => Buffer): string {
  const data = `${b64(header)}.${b64(claims)}`;
  return `${data}.${signer(Buffer.from(data)).toString("base64url")}`;
}

function claims(iss: FakeIssuer, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.trunc(Date.now() / 1000);
  return { iss: iss.issuer, aud: iss.audience, sub: "u1", iat: now, exp: now + 300, ...extra };
}

describe("Verifier", () => {
  const iss = new FakeIssuer({ audience: "agentcanvas" });
  const v = new Verifier({ issuer: iss.issuer, audience: "agentcanvas", jwks: iss.jwks });

  it("verifies tokens and checks permissions", async () => {
    const p = await v.verify(iss.token({ userId: "u1", tenantId: "t1", tenant: "acme", perms: ["workflow.read"], roles: ["viewer"] }));
    assert.equal(p.userId, "u1");
    assert.equal(p.tenantId, "t1");
    assert.equal(p.tenantSlug, "acme");
    assert.ok(p.has("workflow.read"));
    assert.ok(!p.has("workflow.write"));
    assert.ok(p.hasTenantRole("owner", "member"));
    const admin = await v.verify(iss.token({ userId: "u2", tenantId: "t1", perms: ["*"] }));
    assert.ok(admin.has("anything.at.all"));
  });

  const refused: Record<string, () => string> = {
    "wrong audience": () => iss.token({ audience: "devflow" }),
    expired: () => iss.token({ ttl: -120 }),
    "other issuer": () => new FakeIssuer({ issuer: "https://evil", audience: "agentcanvas" }).token(),
    "other key": () => new FakeIssuer({ audience: "agentcanvas" }).token(),
    garbage: () => "not.a.token",
    "two parts": () => "abc.def",
    "missing exp": () => iss.signClaims({ iss: iss.issuer, aud: "agentcanvas", sub: "u" }),
    "missing aud": () => iss.signClaims({ iss: iss.issuer, sub: "u", exp: Date.now() / 1000 + 60 }),
    "missing iss": () => iss.signClaims({ aud: "agentcanvas", sub: "u", exp: Date.now() / 1000 + 60 }),
    "nbf in the future": () => iss.signClaims(claims(iss, { nbf: Date.now() / 1000 + 120 })),
    "audience array without the app": () => iss.signClaims(claims(iss, { aud: ["devflow", "billing"] })),
    "alg none": () => `${b64({ alg: "none", kid: iss.kid })}.${b64(claims(iss))}.`,
    "HS256 with the public key as secret": () =>
      jwt({ alg: "HS256", kid: iss.kid }, claims(iss), (d) => createHmac("sha256", JSON.stringify(iss.jwks.keys[0])).update(d).digest()),
    "RS256 header on a PS256 signature": () => iss.signClaims(claims(iss), { alg: "PS256" }),
  };
  for (const [name, token] of Object.entries(refused)) {
    it(`refuses: ${name}`, async () => {
      await assert.rejects(v.verify(token()), InvalidToken);
    });
  }

  it("accepts an audience array that includes the app, and the leeway", async () => {
    const p = await v.verify(iss.signClaims(claims(iss, { aud: ["devflow", "agentcanvas"] })));
    assert.equal(p.userId, "u1");
    const now = Math.trunc(Date.now() / 1000);
    await v.verify(iss.signClaims(claims(iss, { exp: now - 10, nbf: now + 10 })));
    const strict = new Verifier({ issuer: iss.issuer + "/", audience: "agentcanvas", jwks: iss.jwks, leewaySeconds: 0 });
    await assert.rejects(strict.verify(iss.signClaims(claims(iss, { exp: now - 10 }))), /expired/);
    await strict.verify(iss.token()); // the trailing slash on the issuer is ignored
  });

  it("uses the injected clock", async () => {
    const t = iss.token({ now: 1_000_000, ttl: 60 });
    await assert.rejects(v.verify(t), /expired/);
    const past = new Verifier({ issuer: iss.issuer, audience: "agentcanvas", jwks: iss.jwks, now: () => 1_000_030 });
    await past.verify(t);
  });

  for (const [alg, gen] of [
    ["ES256", () => generateKeyPairSync("ec", { namedCurve: "P-256" })],
    ["ES384", () => generateKeyPairSync("ec", { namedCurve: "P-384" })],
    ["PS256", () => generateKeyPairSync("rsa", { modulusLength: 2048 })],
    ["RS384", () => generateKeyPairSync("rsa", { modulusLength: 2048 })],
    ["RS512", () => generateKeyPairSync("rsa", { modulusLength: 2048 })],
  ] as const) {
    it(`verifies ${alg}`, async () => {
      const { privateKey, publicKey } = gen() as { privateKey: KeyObject; publicKey: KeyObject };
      const jwk = { ...(publicKey.export({ format: "jwk" }) as Jwk), kid: "k-" + alg };
      const hash = { ES256: "sha256", ES384: "sha384", PS256: "sha256", RS384: "sha384", RS512: "sha512" }[alg];
      const signer = (d: Buffer) =>
        alg.startsWith("ES")
          ? cryptoSign(hash, d, { key: privateKey, dsaEncoding: "ieee-p1363" })
          : alg.startsWith("PS")
            ? cryptoSign(hash, d, { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 })
            : cryptoSign(hash, d, privateKey);
      const ver = new Verifier({ issuer: iss.issuer, audience: "agentcanvas", jwks: { keys: [jwk] } });
      const p = await ver.verify(jwt({ alg, kid: jwk.kid }, claims(iss), signer));
      assert.equal(p.userId, "u1");
      if (alg.startsWith("ES")) {
        // DER-encoded ECDSA signatures are not JWS signatures
        const der = jwt({ alg, kid: jwk.kid }, claims(iss), (d) => cryptoSign(hash, d, privateKey));
        await assert.rejects(ver.verify(der), InvalidToken);
      }
    });
  }

  it("refetches the JWKS once on an unknown kid, rate-limited", async () => {
    const a = new FakeIssuer({ audience: "agentcanvas" });
    const b = new FakeIssuer({ issuer: a.issuer, audience: "agentcanvas" });
    let served = a.jwks;
    const srv = await stubServer(() => [200, served]);
    try {
      let now = 1000;
      const ver = new Verifier({ issuer: a.issuer, audience: "agentcanvas", jwksUrl: srv.url + "/certs", now: () => now });
      const tok = (i: FakeIssuer) => i.token({ now });
      await ver.verify(tok(a));
      await ver.verify(tok(a));
      assert.equal(srv.seen.length, 1, "keys are cached");

      served = { keys: [...a.jwks.keys, ...b.jwks.keys] }; // the realm rotated: b's key is new
      now += 11;
      await ver.verify(tok(b));
      assert.equal(srv.seen.length, 2, "an unknown kid refetches");

      const c = new FakeIssuer({ issuer: a.issuer, audience: "agentcanvas" });
      await assert.rejects(ver.verify(tok(c)), /unknown key/);
      await assert.rejects(ver.verify(tok(c)), /unknown key/);
      assert.equal(srv.seen.length, 2, "no refetch within the minimum interval");
      now += 11;
      await assert.rejects(ver.verify(tok(c)), /unknown key/);
      assert.equal(srv.seen.length, 3, "one refetch after the interval");

      now += 301;
      await ver.verify(tok(a));
      assert.equal(srv.seen.length, 4, "the cache expires");
      assert.equal(srv.seen[0]!.url, "/certs");
    } finally {
      await srv.close();
    }
  });

  it("defaults the JWKS URL to the realm's certs endpoint", () => {
    const ver = new Verifier({ issuer: "https://id.example.com/realms/matura/", audience: "x" });
    assert.equal(ver.jwksUrl, "https://id.example.com/realms/matura/protocol/openid-connect/certs");
  });

  it("fails cleanly when the JWKS cannot be fetched", async () => {
    const srv = await stubServer(() => [500, { error: "down" }]);
    try {
      const ver = new Verifier({ issuer: iss.issuer, audience: "agentcanvas", jwksUrl: srv.url });
      await assert.rejects(ver.verify(iss.token()), /cannot find the token's signing key/);
    } finally {
      await srv.close();
    }
  });
});

describe("bearer", () => {
  it("reads the token", () => {
    assert.equal(bearer("Bearer abc"), "abc");
    assert.equal(bearer("bearer   abc "), "abc");
    for (const bad of [undefined, null, "", "Basic abc", "Bearer", "Bearer   "]) {
      assert.throws(() => bearer(bad), InvalidToken);
    }
  });
});

describe("Principal", () => {
  it("expands perms_ref from the role table", () => {
    const p = Principal.fromClaims({ sub: "u", roles: ["editor", "viewer"], perms_ref: "matura_app_role" });
    assert.ok(!p.has("workflow.write"));
    const e = p.expand({ editor: ["workflow.write", "workflow.read"], viewer: ["workflow.read"] });
    assert.deepEqual([...e.permissions], ["workflow.read", "workflow.write"]);
    assert.equal(e.permsRef, null);
    assert.ok(e.has("workflow.write"));
    assert.deepEqual([...p.expand({ editor: ["*"], viewer: ["x"] }).permissions], ["*"]);
    const plain = Principal.fromClaims({ sub: "u", perms: ["a"] });
    assert.equal(plain.expand({ x: ["y"] }), plain);
  });

  it("reads the claims like the Python SDK", () => {
    const p = Principal.fromClaims({
      sub: "u", tid: "t", tenant: "acme", wid: "w", troles: ["admin"], roles: ["r"], perms: ["p"],
      email: "a@x", email_verified: true, name: "A", ver: { u: "12", m: 40, t: 7 }, pmode: "schema",
      amr: ["pwd", "otp"], sid: "s", azp: "devflow",
    });
    assert.deepEqual(
      { ...p, claims: undefined },
      {
        userId: "u", tenantId: "t", tenantSlug: "acme", workspaceId: "w", tenantRoles: ["admin"], roles: ["r"],
        permissions: ["p"], permsRef: null, email: "a@x", emailVerified: true, name: "A", versions: { u: 12, m: 40, t: 7 },
        placementMode: "schema", mfa: true, sessionId: "s", clientId: "devflow", isService: false, claims: undefined,
      },
    );
    assert.ok(Principal.fromClaims({ sub: "u", acr: 2 }).mfa);
    assert.ok(!Principal.fromClaims({ sub: "u", acr: "1", email_verified: "true" }).emailVerified);
    const svc = Principal.fromClaims({ sub: "sa", client_id: "devflow" });
    assert.ok(svc.isService);
    assert.equal(svc.clientId, "devflow");
    assert.equal(svc.email, "");
  });
});
