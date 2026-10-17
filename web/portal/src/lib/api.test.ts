import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient } from "./api";
import { endpoints } from "./endpoints";

function client(responder: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const auth = { headers: vi.fn(async () => ({ Authorization: "Bearer t" })), reauthenticate: vi.fn() };
  const api = createApiClient({
    auth,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init! });
      return responder(String(input), init!);
    }) as typeof fetch,
    idempotencyKey: () => "key-1",
  });
  return { api, calls, auth, ep: endpoints(api) };
}

const problem = (status: number, type: string, detail: string) =>
  new Response(JSON.stringify({ type: `https://matura.dev/problems/${type}`, title: "x", status, detail }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });

describe("api client", () => {
  it("sends auth headers and unwraps item lists", async () => {
    const { ep, calls } = client(() => new Response(JSON.stringify({ items: [{ user_id: "u1" }] })));
    expect(await ep.members("t1")).toEqual([{ user_id: "u1" }]);
    expect(calls[0].url).toBe("/v1/tenants/t1/members");
    expect(calls[0].init.method).toBe("GET");
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe("Bearer t");
  });

  it("adds an Idempotency-Key to POSTs and a JSON body", async () => {
    const { ep, calls } = client(() => new Response(JSON.stringify({ id: "w1" }), { status: 201 }));
    await ep.createWorkspace("t1", "Design");
    const h = calls[0].init.headers as Record<string, string>;
    expect(h["Idempotency-Key"]).toBe("key-1");
    expect(h["Content-Type"]).toBe("application/json");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ name: "Design" });
  });

  it("puts the version in If-Match", async () => {
    const { ep, calls } = client(() => new Response(JSON.stringify({ id: "t1" })));
    await ep.renameTenant("t1", "Acme", 7);
    expect((calls[0].init.headers as Record<string, string>)["If-Match"]).toBe('"7"');
    expect((calls[0].init.headers as Record<string, string>)["Idempotency-Key"]).toBeUndefined();
  });

  it("returns undefined for 204", async () => {
    const { ep } = client(() => new Response(null, { status: 204 }));
    await expect(ep.removeMember("t1", "u1")).resolves.toBeUndefined();
  });

  it("turns problem+json into ApiError", async () => {
    const { ep } = client(() => problem(403, "forbidden", "you do not have permission to do this"));
    const err = await ep.invitations("t1").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(err.code).toBe("forbidden");
    expect(err.forbidden).toBe(true);
    expect(err.message).toBe("you do not have permission to do this");
  });

  it("keeps the status when the error body is not JSON", async () => {
    const { ep } = client(() => new Response("boom", { status: 502, statusText: "Bad Gateway" }));
    const err = await ep.me().catch((e) => e);
    expect(err.status).toBe(502);
    expect(err.message).toBe("Bad Gateway");
  });

  it("starts signing in again on 401", async () => {
    const { ep, auth } = client(() => problem(401, "unauthenticated", "token expired"));
    await expect(ep.me()).rejects.toMatchObject({ status: 401 });
    expect(auth.reauthenticate).toHaveBeenCalledOnce();
  });

  it("reports network failures as ApiError status 0", async () => {
    const { ep } = client(() => {
      throw new TypeError("fetch failed");
    });
    await expect(ep.me()).rejects.toMatchObject({ status: 0, code: "network" });
  });

  it("encodes the resend action and app slugs in paths", async () => {
    const { ep, calls } = client(() => new Response("{}"));
    await ep.resendInvitation("t1", "i1");
    await ep.enableApp("t1", "agent canvas");
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      "POST /v1/tenants/t1/invitations/i1:resend",
      "PUT /v1/tenants/t1/apps/agent%20canvas",
    ]);
  });
});
