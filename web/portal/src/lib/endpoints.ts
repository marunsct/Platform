// One function per API call the portal makes. Paths follow api/openapi.yaml.
import type { ApiClient } from "./api";
import type {
  Agent,
  AgentWithSecret,
  App,
  AuditPage,
  AuditVerification,
  GroupMapping,
  ScimTokenList,
  ScimTokenWithSecret,
  Grant,
  Invitation,
  InvitedRole,
  Items,
  Me,
  Member,
  MyTenant,
  Role,
  Tenant,
  TenantApp,
  TenantRole,
  Workspace,
} from "./types";

const t = (tid: string) => `/v1/tenants/${encodeURIComponent(tid)}`;
const items = <T>(p: Promise<Items<T>>) => p.then((r) => r.items);

export function endpoints(api: ApiClient) {
  return {
    me: () => api.get<Me>("/v1/me"),
    myTenants: () => items(api.get<Items<MyTenant>>("/v1/me/tenants")),

    tenants: () => items(api.get<Items<Tenant>>("/v1/tenants")),
    createTenant: (name: string, slug: string) => api.post<Tenant>("/v1/tenants", { name, slug }),
    tenant: (tid: string) => api.get<Tenant>(t(tid)),
    renameTenant: (tid: string, name: string, version: number) => api.patch<Tenant>(t(tid), { name }, version),

    members: (tid: string) => items(api.get<Items<Member>>(`${t(tid)}/members`)),
    setMemberRole: (tid: string, uid: string, tenant_role: TenantRole) =>
      api.patch<Member>(`${t(tid)}/members/${uid}`, { tenant_role }),
    removeMember: (tid: string, uid: string) => api.del(`${t(tid)}/members/${uid}`),

    invitations: (tid: string) => items(api.get<Items<Invitation>>(`${t(tid)}/invitations`)),
    invite: (tid: string, body: { email: string; tenant_role: TenantRole; app_roles: InvitedRole[] }) =>
      api.post<Invitation>(`${t(tid)}/invitations`, { ...body, delivery: "link" }),
    resendInvitation: (tid: string, id: string) => api.post<Invitation>(`${t(tid)}/invitations/${id}:resend`),
    revokeInvitation: (tid: string, id: string) => api.del(`${t(tid)}/invitations/${id}`),

    apps: () => items(api.get<Items<App>>("/v1/apps")),
    tenantApps: (tid: string) => items(api.get<Items<TenantApp>>(`${t(tid)}/apps`)),
    enableApp: (tid: string, app: string) => api.put<TenantApp>(`${t(tid)}/apps/${encodeURIComponent(app)}`),
    disableApp: (tid: string, app: string) => api.del(`${t(tid)}/apps/${encodeURIComponent(app)}`),

    grants: (tid: string) => items(api.get<Items<Grant>>(`${t(tid)}/grants`)),
    grant: (tid: string, body: { app: string; user_id: string; role: string; workspace_id?: string }) =>
      api.post<Grant>(`${t(tid)}/grants`, body),
    revokeGrant: (tid: string, id: string) => api.del(`${t(tid)}/grants/${id}`),

    workspaces: (tid: string) => items(api.get<Items<Workspace>>(`${t(tid)}/workspaces`)),
    createWorkspace: (tid: string, name: string) => api.post<Workspace>(`${t(tid)}/workspaces`, { name }),
    renameWorkspace: (tid: string, wid: string, name: string) =>
      api.patch<Workspace>(`${t(tid)}/workspaces/${wid}`, { name }),

    roles: (app: string) => items(api.get<Items<Role>>(`/v1/apps/${encodeURIComponent(app)}/roles`)),
    createRole: (app: string, body: { name: string; description: string; permissions: string[] }) =>
      api.post<Role>(`/admin/v1/apps/${encodeURIComponent(app)}/roles`, body),
    updateRole: (app: string, name: string, body: { name?: string; description?: string; permissions?: string[] }) =>
      api.patch<Role>(`/admin/v1/apps/${encodeURIComponent(app)}/roles/${encodeURIComponent(name)}`, body),
    deleteRole: (app: string, name: string) =>
      api.del(`/admin/v1/apps/${encodeURIComponent(app)}/roles/${encodeURIComponent(name)}`),

    agents: (tid: string) => items(api.get<Items<Agent>>(`${t(tid)}/agents`)),
    createAgent: (
      tid: string,
      body: { kind: "service" | "agent"; name: string; description?: string; expires_at?: string; grants?: { app: string; role: string }[] },
    ) => api.post<AgentWithSecret>(`${t(tid)}/agents`, body),
    setAgentStatus: (tid: string, id: string, status: "active" | "deactivated", version: number) =>
      api.patch<Agent>(`${t(tid)}/agents/${id}`, { status }, version),
    rotateAgentSecret: (tid: string, id: string) => api.post<AgentWithSecret>(`${t(tid)}/agents/${id}:rotate-secret`),
    deleteAgent: (tid: string, id: string) => api.del(`${t(tid)}/agents/${id}`),

    audit: (tid: string, q: { actor?: string; action?: string; cursor?: string }) => {
      const p = new URLSearchParams({ limit: "50" });
      for (const [k, v] of Object.entries(q)) if (v) p.set(k, v);
      return api.get<AuditPage>(`${t(tid)}/audit?${p}`);
    },
    verifyAudit: (tid: string) => api.get<AuditVerification>(`${t(tid)}/audit:verify`),

    scimTokens: (tid: string) => api.get<ScimTokenList>(`${t(tid)}/scim/tokens`),
    createScimToken: (tid: string, name: string) => api.post<ScimTokenWithSecret>(`${t(tid)}/scim/tokens`, { name }),
    revokeScimToken: (tid: string, id: string) => api.del(`${t(tid)}/scim/tokens/${id}`),
    groupMappings: (tid: string) => items(api.get<Items<GroupMapping>>(`${t(tid)}/scim/group-mappings`)),
    createGroupMapping: (tid: string, body: { group: string; app: string; role: string }) =>
      api.post<GroupMapping>(`${t(tid)}/scim/group-mappings`, body),
    deleteGroupMapping: (tid: string, id: string) => api.del(`${t(tid)}/scim/group-mappings/${id}`),
  };
}

export type Endpoints = ReturnType<typeof endpoints>;
