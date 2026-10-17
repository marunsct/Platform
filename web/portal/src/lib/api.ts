// HTTP client for maturad's API on the same origin. Errors come back as problem+json (RFC 9457) and surface as
// ApiError; a 401 starts signing in again; every POST carries an Idempotency-Key so a retry never runs twice.
import type { Auth } from "./auth";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly type: string,
    readonly detail: string,
  ) {
    super(detail || `request failed (${status})`);
    this.name = "ApiError";
  }

  /** The last segment of the problem type, e.g. "forbidden", "last-owner", "conflict". */
  get code(): string {
    return this.type.split("/").pop() ?? "";
  }

  get forbidden(): boolean {
    return this.status === 403;
  }

  get notFound(): boolean {
    return this.status === 404;
  }
}

export interface RequestOptions {
  body?: unknown;
  version?: number; // sent as If-Match for optimistic concurrency
  signal?: AbortSignal;
}

export interface ApiClient {
  request<T>(method: string, path: string, opts?: RequestOptions): Promise<T>;
  get<T>(path: string, signal?: AbortSignal): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body?: unknown): Promise<T>;
  patch<T>(path: string, body: unknown, version?: number): Promise<T>;
  del(path: string): Promise<void>;
}

export interface ApiClientOptions {
  auth: Pick<Auth, "headers" | "reauthenticate">;
  fetch?: typeof fetch;
  baseUrl?: string;
  idempotencyKey?: () => string;
}

export function createApiClient(o: ApiClientOptions): ApiClient {
  const doFetch = o.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const base = o.baseUrl ?? "";
  const newKey = o.idempotencyKey ?? (() => crypto.randomUUID());

  async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json", ...(await o.auth.headers()) };
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    if (method === "POST") headers["Idempotency-Key"] = newKey();
    if (opts.version !== undefined) headers["If-Match"] = `"${opts.version}"`;

    let res: Response;
    try {
      res = await doFetch(base + path, { method, headers, body, signal: opts.signal });
    } catch (err) {
      if ((err as Error).name === "AbortError") throw err;
      throw new ApiError(0, "network", "Could not reach the server. Check your connection and try again.");
    }
    if (res.status === 401) {
      o.auth.reauthenticate();
      throw new ApiError(401, "unauthenticated", "Your session ended. Signing you in again…");
    }
    if (!res.ok) throw await toError(res);
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  return {
    request,
    get: (path, signal) => request("GET", path, { signal }),
    post: (path, body) => request("POST", path, { body }),
    put: (path, body) => request("PUT", path, { body }),
    patch: (path, body, version) => request("PATCH", path, { body, version }),
    del: (path) => request<void>("DELETE", path),
  };
}

async function toError(res: Response): Promise<ApiError> {
  let type = "about:blank";
  let detail = "";
  try {
    const p = (await res.json()) as { type?: string; detail?: string; title?: string };
    type = p.type ?? type;
    detail = p.detail ?? p.title ?? "";
  } catch {
    // not problem+json: keep the status
  }
  return new ApiError(res.status, type, detail || res.statusText || `request failed (${res.status})`);
}
