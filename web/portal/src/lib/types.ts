// Shapes of maturad's API responses (api/openapi.yaml).

export type TenantRole = "owner" | "admin" | "member";
export const TENANT_ROLES: TenantRole[] = ["owner", "admin", "member"];

export interface User {
  id: string;
  email: string | null;
  email_verified: boolean;
  display_name: string | null;
  locale: string | null;
  kind: string;
  status: string;
  version: number;
  updated_at: string;
}

export interface Me {
  user: User;
  operator: boolean;
}

export interface Tenant {
  id: string;
  slug: string;
  name: string;
  kind: string;
  status: string;
  plan: string | null;
  data_mode_default: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface MyTenant extends Tenant {
  tenant_role: TenantRole;
}

export interface Workspace {
  id: string;
  tenant_id: string;
  name: string;
  status: string;
  is_default: boolean;
  version: number;
  updated_at: string;
}

export interface Member {
  tenant_id: string;
  user_id: string;
  tenant_role: TenantRole;
  status: string;
  joined_at: string;
  version: number;
  updated_at: string;
  email?: string | null;
  display_name?: string | null;
}

export interface PermissionDef {
  name: string;
  description?: string;
}

export interface App {
  id: string;
  slug: string;
  name: string;
  client_id: string;
  status: string;
  version: number;
  manifest: {
    slug: string;
    name: string;
    permissions?: PermissionDef[];
    default_role: string;
    owner_role?: string;
  };
}

export interface Placement {
  mode: string;
  manager: string;
  state: string;
  location_label: string | null;
}

export interface TenantApp {
  tenant_id: string;
  app_id: string;
  app: string;
  status: string;
  version: number;
  placement?: Placement;
}

export interface Role {
  app: string;
  name: string;
  description: string | null;
  permissions: string[];
  is_default: boolean;
  origin: "manifest" | "platform";
  edited: boolean;
  version: number;
}

export interface Grant {
  id: string;
  tenant_id: string;
  app_id: string;
  app: string;
  workspace_id: string | null;
  subject_type: string;
  subject_id: string;
  role: string;
  status: string;
  version: number;
}

export interface InvitedRole {
  app: string;
  role: string;
  workspace_id?: string;
}

export type InvitationState = "pending" | "accepted" | "revoked" | "expired";

export interface Invitation {
  id: string;
  tenant_id: string;
  email: string;
  tenant_role: TenantRole;
  app_roles: InvitedRole[];
  delivery: string;
  deliver_to: string | null;
  expires_at: string;
  state: InvitationState;
  invited_by: string | null;
  accepted_by: string | null;
  accepted_at: string | null;
  sent_count: number;
  version: number;
  created_at: string;
  accept_url?: string;
}

export interface Items<T> {
  items: T[];
}

export interface Agent {
  id: string;
  tenant_id: string;
  kind: "service" | "agent";
  name: string;
  description: string | null;
  owner_id: string | null;
  client_id: string;
  status: "active" | "deactivated";
  expires_at: string | null;
  secret_rotated_at: string;
  version: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  grants: Grant[];
}

export interface AgentWithSecret extends Agent {
  client_secret: string;
  token_endpoint?: string;
}

export interface AuditEvent {
  id: number;
  tenant_id: string | null;
  seq: number;
  time: string;
  actor: { kind: string; id: string | null; email: string; on_behalf_of?: string };
  action: string;
  target: string;
  request_id: string;
  ip: string;
  user_agent: string;
  data: unknown;
  prev_hash: string;
  hash: string;
  redacted?: boolean;
}

export interface AuditPage {
  items: AuditEvent[];
  next_cursor: string | null;
}

export interface AuditVerification {
  ok: boolean;
  events: number;
  anchor_seq: number;
  anchor_hash: string;
  head_seq: number;
  head_hash: string;
  first_break: { seq: number; reason: string } | null;
}

export interface ScimToken {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  created_by?: string | null;
  created_at: string;
  expires_at?: string | null;
  last_used_at?: string | null;
}

export interface ScimTokenList {
  items: ScimToken[];
  scim_base_url: string;
}

export interface ScimTokenWithSecret extends ScimToken {
  token: string;
  scim_base_url: string;
}

export interface GroupMapping {
  id: string;
  tenant_id: string;
  group: string;
  app: string;
  role: string;
  version: number;
  created_at: string;
}

export interface Domain {
  tenant_id: string;
  domain: string;
  verified: boolean;
  verified_at: string | null;
  last_checked_at: string | null;
  last_error: string | null;
  record_name: string;
  record_value: string;
  version: number;
  created_at: string;
}

export type SSOProtocol = "oidc" | "saml";

export interface SSOConnection {
  tenant_id: string;
  alias: string;
  protocol: SSOProtocol;
  display_name: string;
  config: Record<string, string>;
  default_tenant_role: TenantRole;
  version: number;
  created_at: string;
  updated_at: string;
  idp_hint: string;
  redirect_uri: string;
  entity_id?: string;
  metadata_url?: string;
  has_client_secret: boolean;
}

export interface SSOInput {
  protocol: SSOProtocol;
  display_name: string;
  discovery_url?: string;
  client_id?: string;
  client_secret?: string;
  metadata_url?: string;
  default_tenant_role?: TenantRole;
}
