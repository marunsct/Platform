import { describe, expect, it, vi } from "vitest";
import { DevAuth, OidcAuth, RedirectingError, decodeJwt, safeReturnPath, type KeyValueStore } from "./auth";
import { base64url, challengeFor, createPkce } from "./pkce";

class MemoryStore implements KeyValueStore {
  m = new Map<string, string>();
  getItem(k: string) {
    return this.m.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.m.set(k, v);
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
}

const issuer = "https://id.example/realms/matura";
const discovery = {
  authorization_endpoint: issuer + "/protocol/openid-connect/auth",
  token_endpoint: issuer + "/protocol/openid-connect/token",
  end_session_endpoint: issuer + "/protocol/openid-connect/logout",
};

function jwt(claims: Record<string, unknown>): string {
  const enc = (o: unknown) => base64url(new TextEncoder().encode(JSON.stringify(o)));
  return `${enc({ alg: "none" })}.${enc(claims)}.sig`;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function setup(tokenResponses: Array<Response | (() => Response)> = []) {
  const storage = new MemoryStore();
  const navigate = vi.fn<(url: string) => void>();
  let clock = 1_000_000;
  const tokenBodies: URLSearchParams[] = [];
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/.well-known/openid-configuration")) return json(discovery);
    if (url === discovery.token_endpoint) {
      tokenBodies.push(new URLSearchParams(String(init?.body)));
      const next = tokenResponses.shift();
      if (!next) return json({ error: "invalid_grant" }, 400);
      return typeof next === "function" ? next() : next;
    }
    return new Response("not found", { status: 404 });
  });
  const auth = new OidcAuth(
    { auth: "oidc", issuer, client_id: "matura-console" },
    { fetch: fetch as typeof globalThis.fetch, storage, navigate, origin: "http://localhost:8080", basePath: "/portal", now: () => clock },
  );
  return { auth, storage, navigate, fetch, tokenBodies, tick: (ms: number) => (clock += ms) };
}

async function signIn(s: ReturnType<typeof setup>) {
  await expect(s.auth.login("/portal/members")).rejects.toBeInstanceOf(RedirectingError);
  const url = new URL(s.navigate.mock.calls.at(-1)![0]);
  return s.auth.handleCallback(`?code=abc&state=${url.searchParams.get("state")}`);
}

describe("PKCE", () => {
  it("matches the RFC 7636 appendix B example", async () => {
    expect(await challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });

  it("creates a fresh verifier of valid length each time", async () => {
    const a = await createPkce();
    const b = await createPkce();
    expect(a.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).toBe(await challengeFor(a.verifier));
  });
});

describe("OidcAuth", () => {
  it("redirects with code, S256 challenge and state, keeping only the verifier in session storage", async () => {
    const s = setup();
    await expect(s.auth.login("/portal/members")).rejects.toBeInstanceOf(RedirectingError);
    const url = new URL(s.navigate.mock.calls[0][0]);
    expect(url.origin + url.pathname).toBe(discovery.authorization_endpoint);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("matura-console");
    expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:8080/portal/callback");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const saved = JSON.parse(s.storage.getItem("matura.portal.oidc")!);
    expect(url.searchParams.get("state")).toBe(saved.state);
    expect(url.searchParams.get("code_challenge")).toBe(await challengeFor(saved.verifier));
  });

  it("exchanges the code with the verifier and keeps tokens in memory only", async () => {
    const s = setup([json({ access_token: "at1", refresh_token: "rt1", id_token: jwt({ sub: "u1", email: "a@x.io" }), expires_in: 300 })]);
    expect(await signIn(s)).toBe("/portal/members");
    expect(s.tokenBodies[0].get("grant_type")).toBe("authorization_code");
    expect(s.tokenBodies[0].get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(s.storage.m.size).toBe(0);
    expect(await s.auth.headers()).toEqual({ Authorization: "Bearer at1" });
    expect(s.auth.identity()).toMatchObject({ sub: "u1", email: "a@x.io" });
  });

  it("refuses a callback whose state does not match", async () => {
    const s = setup([json({ access_token: "at1", expires_in: 300 })]);
    await expect(s.auth.login("/portal/")).rejects.toBeInstanceOf(RedirectingError);
    await expect(s.auth.handleCallback("?code=abc&state=forged")).rejects.toThrow(/state/);
    expect(s.tokenBodies).toHaveLength(0);
  });

  it("reports an error returned by the identity provider", async () => {
    const s = setup();
    await expect(s.auth.handleCallback("?error=access_denied&error_description=Denied")).rejects.toThrow("Denied");
  });

  it("refreshes once for concurrent callers when the token is about to expire", async () => {
    const s = setup([
      json({ access_token: "at1", refresh_token: "rt1", expires_in: 60 }),
      json({ access_token: "at2", refresh_token: "rt2", expires_in: 300 }),
    ]);
    await signIn(s);
    s.tick(45_000); // inside the 30 s skew
    const [a, b] = await Promise.all([s.auth.accessToken(), s.auth.accessToken()]);
    expect([a, b]).toEqual(["at2", "at2"]);
    expect(s.tokenBodies).toHaveLength(2);
    expect(s.tokenBodies[1].get("grant_type")).toBe("refresh_token");
    expect(s.tokenBodies[1].get("refresh_token")).toBe("rt1");
  });

  it("signs in again silently when the refresh token is no longer accepted", async () => {
    const s = setup([json({ access_token: "at1", refresh_token: "rt1", expires_in: 60 })]);
    await signIn(s);
    s.tick(120_000);
    await expect(s.auth.accessToken()).rejects.toBeInstanceOf(RedirectingError);
    expect(s.navigate).toHaveBeenCalledTimes(2);
    expect(s.navigate.mock.calls[1][0]).toContain(discovery.authorization_endpoint);
  });

  it("logs out through the end-session endpoint with the id token hint", async () => {
    const s = setup([json({ access_token: "at1", id_token: "idt", expires_in: 300 })]);
    await signIn(s);
    s.auth.signOut();
    await vi.waitFor(() => expect(s.navigate).toHaveBeenCalledTimes(2));
    const url = new URL(s.navigate.mock.calls[1][0]);
    expect(url.searchParams.get("id_token_hint")).toBe("idt");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe("http://localhost:8080/portal/");
  });
});

describe("safeReturnPath", () => {
  it("only follows paths inside the portal", () => {
    expect(safeReturnPath("/portal/members?x=1", "/portal")).toBe("/portal/members?x=1");
    expect(safeReturnPath("https://evil.example/", "/portal")).toBe("/portal/");
    expect(safeReturnPath("//evil.example/portal/", "/portal")).toBe("/portal/");
    expect(safeReturnPath("/portal/callback?code=1", "/portal")).toBe("/portal/");
    expect(safeReturnPath(undefined, "/portal")).toBe("/portal/");
  });
});

describe("decodeJwt", () => {
  it("reads claims and rejects garbage", () => {
    expect(decodeJwt(jwt({ sub: "x", name: "Zoë" }))).toEqual({ sub: "x", name: "Zoë" });
    expect(decodeJwt("nope")).toBeNull();
  });
});

describe("DevAuth", () => {
  it("sends the X-Matura-Dev headers of the chosen identity", async () => {
    const storage = new MemoryStore();
    const auth = new DevAuth({ storage, navigate: vi.fn(), basePath: "/portal" });
    await expect(auth.headers()).rejects.toBeInstanceOf(RedirectingError);
    auth.signIn({ userId: "11111111-1111-1111-1111-111111111111", email: "o@x.io", name: "", operator: true });
    expect(await auth.headers()).toEqual({
      "X-Matura-Dev-User": "11111111-1111-1111-1111-111111111111",
      "X-Matura-Dev-Email": "o@x.io",
      "X-Matura-Dev-Operator": "true",
    });
  });
});
