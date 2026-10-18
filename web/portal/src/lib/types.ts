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
