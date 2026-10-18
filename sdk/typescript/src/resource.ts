/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728) for an app's API or MCP server (TS15).
 *
 * An app that exposes an MCP server, or any API agents call, serves this document at
 * `/.well-known/oauth-protected-resource` and points 401 answers at it, so clients find the Keycloak realm that
 * issues tokens for it. See docs/guide/agents.md.
 */

export const WELL_KNOWN_RESOURCE = "/.well-known/oauth-protected-resource";

/** Where RFC 9728 §3.1 puts a resource's metadata: the well-known path between the host and the resource's path. */
export function metadataUrl(resource: string): string {
  let u: URL;
  try {
    u = new URL(resource);
  } catch {
    throw new TypeError(`resource ${JSON.stringify(resource)} is not an absolute URL`);
  }
  const path = u.pathname.replace(/\/+$/, "");
  return `${u.protocol}//${u.host}${WELL_KNOWN_RESOURCE}${path}`;
}

export interface ResourceMetadataOptions {
  scopesSupported?: readonly string[];
  resourceName?: string;
  resourceDocumentation?: string;
  extra?: Record<string, unknown>;
}

/**
 * The metadata document: `resource` is the app's identifier (its MCP server URL, also listed in the manifest's
 * `auth.resources`), `authorizationServers` the Matura realm's issuer URL.
 */
export function protectedResourceMetadata(
  resource: string, authorizationServers: readonly string[], opts: ResourceMetadataOptions = {},
): Record<string, unknown> {
  if (authorizationServers.length === 0) {
    throw new TypeError("name at least one authorization server (the Matura realm's issuer URL)");
  }
  const doc: Record<string, unknown> = {
    resource, authorization_servers: [...authorizationServers], bearer_methods_supported: ["header"],
  };
  if (opts.scopesSupported?.length) doc["scopes_supported"] = [...opts.scopesSupported];
  if (opts.resourceName) doc["resource_name"] = opts.resourceName;
  if (opts.resourceDocumentation) doc["resource_documentation"] = opts.resourceDocumentation;
  return { ...doc, ...(opts.extra ?? {}) };
}

export interface ChallengeOptions {
  error?: string;
  errorDescription?: string;
  scope?: string;
  realm?: string;
}

function quote(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * The `WWW-Authenticate` value of a 401 (or 403 with `error: "insufficient_scope"`) that points the client at the
 * resource's metadata (RFC 9728 §5.1, RFC 6750 §3).
 */
export function wwwAuthenticate(resource: string, opts: ChallengeOptions = {}): string {
  const params: string[] = [];
  if (opts.realm) params.push(`realm=${quote(opts.realm)}`);
  params.push(`resource_metadata=${quote(metadataUrl(resource))}`);
  if (opts.error) params.push(`error=${quote(opts.error)}`);
  if (opts.errorDescription) params.push(`error_description=${quote(opts.errorDescription)}`);
  if (opts.scope) params.push(`scope=${quote(opts.scope)}`);
  return `Bearer ${params.join(", ")}`;
}
