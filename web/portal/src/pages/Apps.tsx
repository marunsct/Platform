import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppWindow, Plus } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { Card, PageHeader, QueryView, errorText } from "../app/states";
import type { App, Grant, Member, TenantApp, Workspace } from "../lib/types";
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Select, Table, Td, Th, THead, Tr, useToast } from "../ui";
import { memberName } from "./Members";

function GrantDialog({ app, open, onClose, members, workspaces }: { app: App; open: boolean; onClose: () => void; members: Member[]; workspaces: Workspace[] }) {
  const { ep } = useApp();
  const { tid } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const roles = useQuery({ queryKey: keys.roles(app.slug), queryFn: () => ep.roles(app.slug), enabled: open });
  const [user, setUser] = useState("");
  const [role, setRole] = useState("");
  const [ws, setWs] = useState("");
  const [error, setError] = useState("");
  const grant = useMutation({
    mutationFn: () => ep.grant(tid, { app: app.slug, user_id: user, role, ...(ws ? { workspace_id: ws } : {}) }),
    onSuccess: (g) => {
      qc.setQueryData<Grant[]>(keys.grants(tid), (gs) => [...(gs ?? []), g]);
      void qc.invalidateQueries({ queryKey: keys.grants(tid) });
      toast.success("Role granted", `${role} in ${app.name}`);
      setUser("");
      setRole("");
      setWs("");
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Grant a role in ${app.name}`}
      description="The member gets the role's permissions in their next token."
      onSubmit={() => {
        setError("");
        if (!user || !role) return setError("Choose a member and a role.");
        grant.mutate();
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={grant.isPending}>
            Grant
          </Button>
        </>
      }
    >
      <Field label="Member">
        {(id) => (
          <Select id={id} value={user} onChange={(e) => setUser(e.target.value)} autoFocus>
            <option value="">Choose a member…</option>
            {members
              .filter((m) => m.status === "active")
              .map((m) => (
                <option key={m.user_id} value={m.user_id}>
                  {memberName(m)}
                  {m.display_name && m.email ? ` (${m.email})` : ""}
                </option>
              ))}
          </Select>
        )}
      </Field>
      <Field label="Role" error={error || undefined} hint={roles.data?.find((r) => r.name === role)?.description ?? undefined}>
        {(id) => (
          <Select id={id} value={role} onChange={(e) => setRole(e.target.value)} disabled={roles.isPending}>
            <option value="">{roles.isPending ? "Loading roles…" : "Choose a role…"}</option>
            {roles.data?.map((r) => (
              <option key={r.name} value={r.name}>
                {r.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label="Where" hint="A role for one workspace applies only there.">
        {(id) => (
          <Select id={id} value={ws} onChange={(e) => setWs(e.target.value)}>
            <option value="">Whole organisation</option>
            {workspaces
              .filter((w) => w.status === "active")
              .map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
          </Select>
        )}
      </Field>
    </Dialog>
  );
}

function AppCard({ app, ta, grants, members, workspaces }: { app: App; ta?: TenantApp; grants: Grant[]; members: Member[]; workspaces: Workspace[] }) {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const [granting, setGranting] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [revoking, setRevoking] = useState<Grant | null>(null);
  const enabled = ta?.status === "enabled";
  const toggle = useMutation({
    mutationFn: async () => void (enabled ? await ep.disableApp(tid, app.slug) : await ep.enableApp(tid, app.slug)),
    onSuccess: () => {
      setDisabling(false);
      void qc.invalidateQueries({ queryKey: keys.tenantApps(tid) });
      toast.success(`${app.name} ${enabled ? "disabled" : "enabled"}`);
    },
    onError: (e) => toast.error(`Couldn't ${enabled ? "disable" : "enable"} ${app.name}`, errorText(e)),
  });
  const revoke = useMutation({
    mutationFn: (g: Grant) => ep.revokeGrant(tid, g.id),
    onMutate: async (g) => {
      await qc.cancelQueries({ queryKey: keys.grants(tid) });
      const prev = qc.getQueryData<Grant[]>(keys.grants(tid));
      qc.setQueryData<Grant[]>(keys.grants(tid), (gs) => gs?.filter((x) => x.id !== g.id));
      setRevoking(null);
      return { prev };
    },
    onError: (e, _g, ctx) => {
      qc.setQueryData(keys.grants(tid), ctx?.prev);
      toast.error("Couldn't revoke the role", errorText(e));
    },
    onSuccess: () => toast.success("Role revoked"),
  });
  const appGrants = grants.filter((g) => g.app === app.slug && g.status === "active");
  const byId = new Map(members.map((m) => [m.user_id, m]));
  const wsName = new Map(workspaces.map((w) => [w.id, w.name]));

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3 p-4">
        <span className="inline-flex size-8 items-center justify-center rounded-md border border-border bg-bg-subtle text-fg-muted">
          <AppWindow className="size-4" aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium text-fg">{app.name}</span>
            <Badge tone={enabled ? "success" : "neutral"}>{enabled ? "enabled" : "disabled"}</Badge>
            {enabled && ta?.placement ? <Badge>{ta.placement.mode} · {ta.placement.state}</Badge> : null}
          </div>
          <div className="font-mono text-xs text-fg-muted">{app.slug}</div>
        </div>
        {canManage ? (
          <div className="flex gap-2">
            {enabled ? (
              <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => setGranting(true)}>
                Grant role
              </Button>
            ) : null}
            <Button size="sm" variant={enabled ? "ghost" : "primary"} loading={toggle.isPending} onClick={() => (enabled ? setDisabling(true) : toggle.mutate())}>
              {enabled ? "Disable" : "Enable"}
            </Button>
          </div>
        ) : null}
      </div>
      {enabled ? (
        <div className="border-t border-border">
          {appGrants.length === 0 ? (
            <p className="px-4 py-3 text-[13px] text-fg-muted">
              No one holds a role here yet. New members get the default role, <span className="font-medium">{app.manifest.default_role}</span>
              {app.manifest.owner_role ? (
                <>
                  ; owners and admins act as <span className="font-medium">{app.manifest.owner_role}</span>
                </>
              ) : null}
              .
            </p>
          ) : (
            <Table className="rounded-none border-0">
              <THead>
                <tr>
                  <Th>Member</Th>
                  <Th>Role</Th>
                  <Th className="hidden sm:table-cell">Where</Th>
                  <Th className="w-24" aria-label="Actions" />
                </tr>
              </THead>
              <tbody>
                {appGrants.map((g) => {
                  const m = byId.get(g.subject_id);
                  return (
                    <Tr key={g.id}>
                      <Td className="font-medium text-fg">{m ? memberName(m) : <span className="font-mono text-xs">{g.subject_id.slice(0, 8)}</span>}</Td>
                      <Td>
                        <Badge tone="accent">{g.role}</Badge>
                      </Td>
                      <Td className="hidden text-fg-muted sm:table-cell">{g.workspace_id ? (wsName.get(g.workspace_id) ?? "a workspace") : "Whole organisation"}</Td>
                      <Td className="text-right">
                        {canManage ? (
                          <Button size="sm" variant="ghost" onClick={() => setRevoking(g)}>
                            Revoke
                          </Button>
                        ) : null}
                      </Td>
                    </Tr>
                  );
                })}
              </tbody>
            </Table>
          )}
        </div>
      ) : null}
      {canManage ? <GrantDialog app={app} open={granting} onClose={() => setGranting(false)} members={members} workspaces={workspaces} /> : null}
      <ConfirmDialog
        open={disabling}
        onClose={() => setDisabling(false)}
        onConfirm={() => toggle.mutate()}
        loading={toggle.isPending}
        danger
        title={`Disable ${app.name}?`}
        description="Members can no longer sign in to it for this organisation. Its data and role grants stay, so enabling it again restores access."
        confirmLabel="Disable"
      />
      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking)}
        danger
        title="Revoke this role?"
        description={revoking ? `${byId.get(revoking.subject_id) ? memberName(byId.get(revoking.subject_id)!) : "The member"} loses ${revoking.role} in ${app.name} at their next token refresh.` : ""}
        confirmLabel="Revoke"
      />
    </Card>
  );
}

export function AppsPage() {
  const { ep } = useApp();
  const { tid } = useCurrentTenant();
  const apps = useQuery({ queryKey: keys.apps, queryFn: ep.apps, staleTime: 300_000 });
  const tenantApps = useQuery({ queryKey: keys.tenantApps(tid), queryFn: () => ep.tenantApps(tid) });
  const grants = useQuery({ queryKey: keys.grants(tid), queryFn: () => ep.grants(tid) });
  const members = useQuery({ queryKey: keys.members(tid), queryFn: () => ep.members(tid) });
  const workspaces = useQuery({ queryKey: keys.workspaces(tid), queryFn: () => ep.workspaces(tid) });
  return (
    <>
      <PageHeader title="App access" description="Turn apps on for this organisation and decide who holds which role in each." />
      <QueryView query={tenantApps} forbidden="manage apps">
        {(tas) => (
          <QueryView query={apps}>
            {(all) =>
              all.length === 0 ? (
                <EmptyState icon={<AppWindow />} title="No apps registered">
                  An operator registers apps from their manifest (<span className="font-mono">PUT /admin/v1/apps/&#123;slug&#125;</span>).
                </EmptyState>
              ) : (
                <div className="flex flex-col gap-3">
                  {[...all]
                    .sort((a, b) => Number(tas.some((t) => t.app === b.slug && t.status === "enabled")) - Number(tas.some((t) => t.app === a.slug && t.status === "enabled")) || a.name.localeCompare(b.name))
                    .map((a) => (
                      <AppCard key={a.slug} app={a} ta={tas.find((t) => t.app === a.slug)} grants={grants.data ?? []} members={members.data ?? []} workspaces={workspaces.data ?? []} />
                    ))}
                </div>
              )
            }
          </QueryView>
        )}
      </QueryView>
    </>
  );
}
