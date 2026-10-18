import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { useApp } from "./context";
import type { Tenant, TenantRole } from "../lib/types";

export type SwitcherTenant = Tenant & { tenant_role: TenantRole | "operator" };

export const keys = {
  me: ["me"] as const,
  tenants: ["tenants"] as const,
  apps: ["apps"] as const,
  tenant: (tid: string) => ["tenant", tid] as const,
  members: (tid: string) => ["tenant", tid, "members"] as const,
  invitations: (tid: string) => ["tenant", tid, "invitations"] as const,
  tenantApps: (tid: string) => ["tenant", tid, "apps"] as const,
  grants: (tid: string) => ["tenant", tid, "grants"] as const,
  workspaces: (tid: string) => ["tenant", tid, "workspaces"] as const,
  agents: (tid: string) => ["tenant", tid, "agents"] as const,
  audit: (tid: string, actor: string, action: string) => ["tenant", tid, "audit", actor, action] as const,
  auditVerify: (tid: string) => ["tenant", tid, "audit", "verify"] as const,
  scimTokens: (tid: string) => ["tenant", tid, "scim", "tokens"] as const,
  groupMappings: (tid: string) => ["tenant", tid, "scim", "mappings"] as const,
  domains: (tid: string) => ["tenant", tid, "domains"] as const,
  sso: (tid: string) => ["tenant", tid, "sso"] as const,
  roles: (app: string) => ["roles", app] as const,
};

export function useMe() {
  const { ep } = useApp();
  return useQuery({ queryKey: keys.me, queryFn: ep.me, staleTime: 60_000 });
}

/** Tenants for the switcher: the user's own; operators see every tenant (as "operator" where not a member). */
export function useTenants() {
  const { ep } = useApp();
  const me = useMe();
  return useQuery({
    queryKey: keys.tenants,
    enabled: me.isSuccess,
    staleTime: 60_000,
    queryFn: async (): Promise<SwitcherTenant[]> => {
      const mine: SwitcherTenant[] = await ep.myTenants();
      if (!me.data?.operator) return mine;
      const all = await ep.tenants();
      const byId = new Map(mine.map((t) => [t.id, t]));
      return all.map((t) => byId.get(t.id) ?? { ...t, tenant_role: "operator" });
    },
  });
}

export function useTenantId(): string {
  return useParams({ strict: false, select: (p: { tid?: string }) => p.tid ?? "" });
}

/** The current tenant and what the signed-in user may do in it. */
export function useCurrentTenant() {
  const tid = useTenantId();
  const tenants = useTenants();
  const me = useMe();
  const entry = tenants.data?.find((t) => t.id === tid);
  const role = me.data?.operator ? "operator" : entry?.tenant_role;
  return {
    tid,
    entry,
    role,
    canManage: role === "owner" || role === "admin" || role === "operator",
    isOwner: role === "owner" || role === "operator",
    operator: !!me.data?.operator,
    meId: me.data?.user.id,
  };
}
