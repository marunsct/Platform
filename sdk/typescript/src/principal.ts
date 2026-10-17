/** The verified caller of a request (contract §2, §8). */

export type Claims = Record<string, unknown>;

export interface PrincipalInit {
  userId: string;
  tenantId: string | null;
  tenantSlug: string | null;
  workspaceId: string | null;
  tenantRoles: readonly string[];
  roles: readonly string[];
  permissions: readonly string[];
  permsRef?: string | null;
  email?: string;
  emailVerified?: boolean;
  name?: string | null;
  versions?: Readonly<Record<string, number>>;
  placementMode?: string | null;
  mfa?: boolean;
  sessionId?: string | null;
  clientId?: string | null;
  isService?: boolean;
  claims?: Claims;
}

function strOrNull(v: unknown): string | null {
  return v === undefined || v === null ? null : String(v);
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.map(String) : [];
}

/**
 * Who is calling and what they may do, read from a verified Matura access token.
 *
 * Apps check `permissions` (the token's `perms`), never role names: roles are defined and edited in Matura,
 * permissions are what the app's code declares (ADR 0008).
 */
export class Principal {
  readonly userId: string;
  readonly tenantId: string | null;
  readonly tenantSlug: string | null;
  readonly workspaceId: string | null;
  readonly tenantRoles: readonly string[];
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
  readonly permsRef: string | null;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name: string | null;
  readonly versions: Readonly<Record<string, number>>;
  readonly placementMode: string | null;
  readonly mfa: boolean;
  readonly sessionId: string | null;
  readonly clientId: string | null;
  readonly isService: boolean;
  readonly claims: Claims;

  constructor(init: PrincipalInit) {
    this.userId = init.userId;
    this.tenantId = init.tenantId;
    this.tenantSlug = init.tenantSlug;
    this.workspaceId = init.workspaceId;
    this.tenantRoles = Object.freeze([...init.tenantRoles]);
    this.roles = Object.freeze([...init.roles]);
    this.permissions = Object.freeze([...init.permissions]);
    this.permsRef = init.permsRef ?? null;
    this.email = init.email ?? "";
    this.emailVerified = init.emailVerified ?? false;
    this.name = init.name ?? null;
    this.versions = Object.freeze({ ...(init.versions ?? {}) });
    this.placementMode = init.placementMode ?? null;
    this.mfa = init.mfa ?? false;
    this.sessionId = init.sessionId ?? null;
    this.clientId = init.clientId ?? null;
    this.isService = init.isService ?? false;
    this.claims = init.claims ?? {};
  }

  /** Build a principal from verified token claims (same rules as the Python SDK's `Principal.from_claims`). */
  static fromClaims(c: Claims): Principal {
    const amr = strings(c["amr"]);
    const ver = c["ver"];
    const versions: Record<string, number> = {};
    if (ver && typeof ver === "object" && !Array.isArray(ver)) {
      for (const [k, v] of Object.entries(ver as Record<string, unknown>)) versions[k] = Math.trunc(Number(v));
    }
    const acr = c["acr"] === undefined || c["acr"] === null ? "" : String(c["acr"]);
    return new Principal({
      userId: String(c["sub"]),
      tenantId: strOrNull(c["tid"]),
      tenantSlug: strOrNull(c["tenant"]),
      workspaceId: strOrNull(c["wid"]),
      tenantRoles: strings(c["troles"]),
      roles: strings(c["roles"]),
      permissions: strings(c["perms"]),
      permsRef: strOrNull(c["perms_ref"]),
      email: c["email"] ? String(c["email"]) : "",
      emailVerified: c["email_verified"] === true,
      name: strOrNull(c["name"]),
      versions,
      placementMode: strOrNull(c["pmode"]),
      mfa: amr.includes("mfa") || amr.includes("otp") || amr.includes("hwk") || acr === "2" || acr === "3",
      sessionId: strOrNull(c["sid"]),
      clientId: strOrNull(c["azp"] || c["client_id"] || null),
      isService: "client_id" in c && !("email" in c),
      claims: c,
    });
  }

  /** True when the token grants `permission` (or `*`). With `permsRef` call {@link expand} first. */
  has(permission: string): boolean {
    return this.permissions.includes("*") || this.permissions.includes(permission);
  }

  /** True when the caller has any of the tenant roles (`owner`, `admin`, `billing`, `member`). */
  hasTenantRole(...roles: string[]): boolean {
    return roles.some((r) => this.tenantRoles.includes(r));
  }

  /** Fill `permissions` from the app's role table when the token carried `perms_ref` (over 40 permissions). */
  expand(rolePermissions: Readonly<Record<string, readonly string[]>>): Principal {
    if (!this.permsRef) return this;
    const perms = new Set<string>();
    for (const r of this.roles) for (const p of rolePermissions[r] ?? []) perms.add(p);
    const out = perms.has("*") ? ["*"] : [...perms].sort();
    return new Principal({ ...this, permissions: out, permsRef: null });
  }
}
