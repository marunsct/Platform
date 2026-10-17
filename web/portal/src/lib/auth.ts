// Sign-in for the portal. OIDC: authorization code with PKCE as the public client from /portal/config.json; tokens
// live in memory only, are refreshed before they expire, and when that fails the browser goes back through the
// identity provider, which signs the user straight in again while its session lasts ("silent re-login").
// Dev: maturad runs with MATURA_AUTH=dev and trusts X-Matura-Dev-* headers; only for local development.
import { createPkce, randomString } from "./pkce";

export interface PortalConfig {
  auth: "oidc" | "dev";
  issuer: string;
  client_id: string;
  product?: string;
}

export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface AuthEnv {
  fetch: typeof fetch;
  storage: KeyValueStore; // sessionStorage: holds only the in-flight PKCE verifier and state, or the dev identity
  navigate: (url: string) => void;
  origin: string;
  basePath: string; // "/portal"
  now?: () => number;
}

export interface Identity {
  sub: string;
  email?: string;
  name?: string;
}

export interface Auth {
  readonly kind: "oidc" | "dev";
  /** Headers that authenticate an API request; may refresh tokens first. */
  headers(): Promise<Record<string, string>>;
  /** Called when the API answered 401: start signing in again. */
  reauthenticate(): void;
  identity(): Identity | null;
  signOut(): void;
}

/** Thrown while the browser is leaving for the identity provider. */
export class RedirectingError extends Error {
  constructor() {
    super("redirecting to sign in");
  }
}

const FLOW_KEY = "matura.portal.oidc";
const SKEW_MS = 30_000;

interface Endpoints {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint?: string;
}

interface Tokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
}

export function decodeJwt(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    const json = new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export class OidcAuth implements Auth {
  readonly kind = "oidc";
  private tokens: Tokens | null = null;
  private endpoints: Promise<Endpoints> | null = null;
  private refreshing: Promise<Tokens> | null = null;
  private readonly now: () => number;

  constructor(
    private readonly cfg: PortalConfig,
    private readonly env: AuthEnv,
  ) {
    this.now = env.now ?? Date.now;
  }

  get redirectUri(): string {
    return this.env.origin + this.env.basePath + "/callback";
  }

  get signedIn(): boolean {
    return this.tokens !== null;
  }

  private discover(): Promise<Endpoints> {
    this.endpoints ??= this.env
      .fetch(this.cfg.issuer.replace(/\/$/, "") + "/.well-known/openid-configuration")
      .then(async (res) => {
        if (!res.ok) throw new Error(`identity provider discovery failed (${res.status})`);
        return (await res.json()) as Endpoints;
      })
      .catch((err) => {
        this.endpoints = null;
        throw err;
      });
    return this.endpoints;
  }

  /** Sends the browser to the identity provider; returnTo is the portal path to come back to. */
  async login(returnTo: string, extra: Record<string, string> = {}): Promise<never> {
    const ep = await this.discover();
    const { verifier, challenge } = await createPkce();
    const state = randomString(16);
    this.env.storage.setItem(FLOW_KEY, JSON.stringify({ verifier, state, returnTo }));
    const q = new URLSearchParams({
      response_type: "code",
      client_id: this.cfg.client_id,
      redirect_uri: this.redirectUri,
      scope: "openid email profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      ...extra,
    });
    this.env.navigate(ep.authorization_endpoint + "?" + q.toString());
    throw new RedirectingError();
  }

  /** Completes the redirect back from the identity provider and returns the path to continue at. */
  async handleCallback(search: string): Promise<string> {
    const params = new URLSearchParams(search);
    const raw = this.env.storage.getItem(FLOW_KEY);
    this.env.storage.removeItem(FLOW_KEY); // a code and verifier are good for one try only
    const saved = raw ? (JSON.parse(raw) as { verifier: string; state: string; returnTo: string }) : null;
    if (params.get("error")) {
      throw new Error(params.get("error_description") || params.get("error") || "sign-in failed");
    }
    const code = params.get("code");
    if (!saved || !code || params.get("state") !== saved.state) {
      throw new Error("sign-in did not complete (state mismatch); try again");
    }
    const ep = await this.discover();
    this.tokens = await this.tokenRequest(ep, {
      grant_type: "authorization_code",
      code,
      client_id: this.cfg.client_id,
      redirect_uri: this.redirectUri,
      code_verifier: saved.verifier,
    });
    return safeReturnPath(saved.returnTo, this.env.basePath);
  }

  private async tokenRequest(ep: Endpoints, body: Record<string, string>): Promise<Tokens> {
    const res = await this.env.fetch(ep.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });
    if (!res.ok) throw new Error(`token request failed (${res.status})`);
    const t = (await res.json()) as TokenResponse;
    return {
      accessToken: t.access_token,
      refreshToken: t.refresh_token,
      idToken: t.id_token ?? this.tokens?.idToken,
      expiresAt: this.now() + (t.expires_in ?? 60) * 1000,
    };
  }

  private refresh(): Promise<Tokens> {
    const current = this.tokens;
    if (!current?.refreshToken) return Promise.reject(new Error("no refresh token"));
    this.refreshing ??= this.discover()
      .then((ep) =>
        this.tokenRequest(ep, {
          grant_type: "refresh_token",
          refresh_token: current.refreshToken!,
          client_id: this.cfg.client_id,
        }),
      )
      .then((t) => (this.tokens = t))
      .finally(() => (this.refreshing = null));
    return this.refreshing;
  }

  /** A valid access token, refreshed when close to expiry; signs in again when refreshing fails. */
  async accessToken(): Promise<string> {
    const t = this.tokens;
    if (t && t.expiresAt - this.now() > SKEW_MS) return t.accessToken;
    if (t?.refreshToken) {
      try {
        return (await this.refresh()).accessToken;
      } catch {
        this.tokens = null;
      }
    }
    return this.login(this.currentPath());
  }

  async headers(): Promise<Record<string, string>> {
    return { Authorization: "Bearer " + (await this.accessToken()) };
  }

  reauthenticate(): void {
    this.tokens = null;
    void this.login(this.currentPath()).catch(() => {});
  }

  identity(): Identity | null {
    const c = this.tokens && decodeJwt(this.tokens.idToken ?? this.tokens.accessToken);
    if (!c) return null;
    return { sub: String(c.sub ?? ""), email: c.email as string | undefined, name: c.name as string | undefined };
  }

  signOut(): void {
    const idToken = this.tokens?.idToken;
    this.tokens = null;
    void this.discover().then((ep) => {
      if (!ep.end_session_endpoint) return this.env.navigate(this.env.basePath + "/");
      const q = new URLSearchParams({
        client_id: this.cfg.client_id,
        post_logout_redirect_uri: this.env.origin + this.env.basePath + "/",
      });
      if (idToken) q.set("id_token_hint", idToken);
      this.env.navigate(ep.end_session_endpoint + "?" + q.toString());
    });
  }

  private currentPath(): string {
    return typeof location === "undefined" ? this.env.basePath + "/" : location.pathname + location.search;
  }
}

/** Only same-portal paths are followed after sign-in, so a crafted state cannot send the user elsewhere. */
export function safeReturnPath(p: string | undefined, basePath: string): string {
  if (!p || !p.startsWith(basePath + "/") || p.startsWith("//") || p.includes("\\")) return basePath + "/";
  if (p.startsWith(basePath + "/callback")) return basePath + "/";
  return p;
}

export interface DevIdentity {
  userId: string;
  email: string;
  name: string;
  operator: boolean;
}

const DEV_KEY = "matura.portal.dev";

export class DevAuth implements Auth {
  readonly kind = "dev";
  constructor(private readonly env: Pick<AuthEnv, "storage" | "navigate" | "basePath">) {}

  current(): DevIdentity | null {
    const raw = this.env.storage.getItem(DEV_KEY);
    return raw ? (JSON.parse(raw) as DevIdentity) : null;
  }

  signIn(id: DevIdentity): void {
    this.env.storage.setItem(DEV_KEY, JSON.stringify(id));
  }

  async headers(): Promise<Record<string, string>> {
    const id = this.current();
    if (!id) throw new RedirectingError();
    const h: Record<string, string> = { "X-Matura-Dev-User": id.userId };
    if (id.email) h["X-Matura-Dev-Email"] = id.email;
    if (id.name) h["X-Matura-Dev-Name"] = id.name;
    if (id.operator) h["X-Matura-Dev-Operator"] = "true";
    return h;
  }

  reauthenticate(): void {
    this.signOut();
  }

  identity(): Identity | null {
    const id = this.current();
    return id ? { sub: id.userId, email: id.email, name: id.name } : null;
  }

  signOut(): void {
    this.env.storage.removeItem(DEV_KEY);
    this.env.navigate(this.env.basePath + "/");
  }
}
