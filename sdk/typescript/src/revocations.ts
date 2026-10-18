/** Instant revocation (technical specification §21): refuse tokens Matura revoked before they expire. */

/** How long a revocation matters: the longest token lifetime plus skew, with margin (seconds). */
export const REVOCATION_WINDOW_SECONDS = 15 * 60;

export interface Revocation {
  id: string;
  user_id: string;
  /** Only tokens this agent got for `user_id` (a consent withdrawn). */
  actor_id?: string | null;
  tenant_id?: string | null;
  session_id?: string | null;
  /** RFC 3339 time: tokens issued at or before it are revoked. */
  not_before: string;
  reason?: string;
}

function seconds(t: string): number {
  return Date.parse(t) / 1000;
}

/**
 * Whether a revocation stops a token with these claims: `sub` (or `act.sub`) is its user, `tid` its tenant when it
 * names one, `sid` its session when it names one, and `iat` is at or before `not_before`.
 */
export function covers(r: Revocation, claims: Record<string, unknown>): boolean {
  const iat = claims["iat"];
  if (typeof iat !== "number" || !iat) return false;
  const act = claims["act"];
  const actSub = act && typeof act === "object" ? (act as Record<string, unknown>)["sub"] : undefined;
  if (r.actor_id) {
    if (r.user_id !== claims["sub"] || actSub !== r.actor_id) return false;
  } else if (r.user_id !== claims["sub"] && r.user_id !== actSub) return false;
  if (r.tenant_id && r.tenant_id !== claims["tid"]) return false;
  if (r.session_id && r.session_id !== claims["sid"]) return false;
  return iat <= seconds(r.not_before);
}

/**
 * Recent revocations a {@link Verifier} consults (`new Verifier({ …, revocations })`). Fill it at start with `load`
 * and keep it current with `apply` (the webhook handler and {@link Sync} call it when given `revocations`) or by
 * loading every few seconds.
 */
export class Revocations {
  private readonly byId = new Map<string, Revocation>();
  private readonly clock: () => number;

  constructor(opts: { now?: () => number } = {}) {
    this.clock = opts.now ?? (() => Date.now() / 1000);
  }

  add(...revocations: Revocation[]): void {
    const cutoff = this.clock() - REVOCATION_WINDOW_SECONDS;
    for (const [id, r] of this.byId) if (seconds(r.not_before) < cutoff) this.byId.delete(id);
    for (const r of revocations) {
      if (r && r.id && r.user_id && seconds(r.not_before) >= cutoff) this.byId.set(r.id, r);
    }
  }

  /** Add the revocation a `matura.revocation.created` event carries; other events are ignored. */
  apply(event: Record<string, unknown>): boolean {
    if (event["type"] !== "matura.revocation.created") return false;
    const data = event["data"];
    const r = data && typeof data === "object" ? (data as Record<string, unknown>)["revocation"] : undefined;
    if (!r || typeof r !== "object") return false;
    this.add(r as Revocation);
    return true;
  }

  revoked(claims: Record<string, unknown>): boolean {
    for (const r of this.byId.values()) if (covers(r, claims)) return true;
    return false;
  }

  get size(): number {
    return this.byId.size;
  }

  /** Fetch the app's recent revocations (`GET /v1/apps/{app}/revocations`). */
  async load(api: { revocations(app: string): Promise<{ items: Revocation[] }> }, app: string): Promise<void> {
    const page = await api.revocations(app);
    this.add(...(page.items ?? []));
  }
}
