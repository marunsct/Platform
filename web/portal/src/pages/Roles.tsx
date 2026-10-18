import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, ShieldCheck } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { Card, PageHeader, QueryView, errorText } from "../app/states";
import type { App, PermissionDef, Role } from "../lib/types";
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Input, cx, useToast } from "../ui";

function catalogue(app: App, roles: Role[]): PermissionDef[] {
  if (app.manifest.permissions?.length) return app.manifest.permissions;
  const names = [...new Set(roles.flatMap((r) => r.permissions))].sort();
  return names.map((name) => ({ name }));
}

function RoleDialog({ app, perms, role, open, onClose }: { app: App; perms: PermissionDef[]; role: Role | null; open: boolean; onClose: () => void }) {
  const { ep } = useApp();
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  const [seed, setSeed] = useState<string | null>(null);
  const key = open ? (role?.name ?? "") + "|" + String(open) : null;
  if (key !== seed) {
    setSeed(key);
    setName(role?.name ?? "");
    setDescription(role?.description ?? "");
    setChosen(new Set(role?.permissions ?? []));
    setError("");
  }
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description: description.trim(), permissions: [...chosen].sort() };
      if (!role) return ep.createRole(app.slug, body);
      return ep.updateRole(app.slug, role.name, { ...(body.name !== role.name ? { name: body.name } : {}), description: body.description, permissions: body.permissions });
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: keys.roles(app.slug) });
      toast.success(role ? `Role ${r.name} saved` : `Role ${r.name} created`);
      onClose();
    },
    onError: (e) => setError(errorText(e)),
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={role ? `Edit ${role.name}` : `New role in ${app.name}`}
      description="Roles apply in every organisation using this app. Changes reach apps in the next token."
      className="w-[min(520px,calc(100vw-32px))]"
      onSubmit={() => {
        setError("");
        if (!name.trim()) return setError("Give the role a name.");
        save.mutate();
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            {role ? "Save" : "Create role"}
          </Button>
        </>
      }
    >
      <Field label="Name">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus placeholder="e.g. reviewer" />}</Field>
      <Field label="Description">{(id) => <Input id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
      <fieldset>
        <legend className="mb-2 text-xs font-medium text-fg">Permissions</legend>
        {perms.length === 0 ? <p className="text-xs text-fg-muted">This app's manifest declares no permissions.</p> : null}
        <div className="flex max-h-64 flex-col gap-1 overflow-y-auto">
          {perms.map((p) => (
            <label key={p.name} className="flex cursor-pointer items-start gap-2.5 rounded-md px-2 py-1.5 hover:bg-bg-muted">
              <input
                type="checkbox"
                className="mt-0.5 accent-[var(--accent)]"
                checked={chosen.has(p.name)}
                onChange={(e) => {
                  const next = new Set(chosen);
                  if (e.target.checked) next.add(p.name);
                  else next.delete(p.name);
                  setChosen(next);
                }}
              />
              <span>
                <span className="font-mono text-xs text-fg">{p.name}</span>
                {p.description ? <span className="block text-xs text-fg-muted">{p.description}</span> : null}
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      {error ? <p className="text-xs text-danger">{error}</p> : null}
    </Dialog>
  );
}

function AppRoles({ app }: { app: App }) {
  const { ep } = useApp();
  const { operator } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const roles = useQuery({ queryKey: keys.roles(app.slug), queryFn: () => ep.roles(app.slug) });
  const [editing, setEditing] = useState<Role | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Role | null>(null);
  const del = useMutation({
    mutationFn: (r: Role) => ep.deleteRole(app.slug, r.name),
    onSuccess: (_x, r) => {
      setDeleting(null);
      void qc.invalidateQueries({ queryKey: keys.roles(app.slug) });
      toast.success(`Role ${r.name} deleted`);
    },
    onError: (e) => {
      setDeleting(null);
      toast.error("Couldn't delete the role", errorText(e));
    },
  });
  return (
    <QueryView query={roles}>
      {(list) => {
        const perms = catalogue(app, list);
        return (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[13px] text-fg-muted">
                {list.length} role{list.length === 1 ? "" : "s"} · {perms.length} permission{perms.length === 1 ? "" : "s"} in the catalogue
              </p>
              {operator ? (
                <Button size="sm" variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setCreating(true)}>
                  New role
                </Button>
              ) : null}
            </div>
            {list.length === 0 ? (
              <EmptyState icon={<ShieldCheck />} title="No roles" />
            ) : (
              list.map((r) => (
                <Card key={r.name} className="p-4">
                  <div className="flex flex-wrap items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-medium text-fg">{r.name}</span>
                        {r.is_default ? <Badge tone="accent">default</Badge> : null}
                        {app.manifest.owner_role === r.name ? <Badge tone="accent">owners and admins</Badge> : null}
                        <Badge>{r.origin === "manifest" ? (r.edited ? "manifest, edited" : "from manifest") : "custom"}</Badge>
                      </div>
                      {r.description ? <p className="mt-1 text-[13px] text-fg-muted">{r.description}</p> : null}
                    </div>
                    {operator ? (
                      <div className="flex gap-1">
                        <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setDeleting(r)} disabled={r.is_default} title={r.is_default ? "The default role cannot be deleted" : undefined}>
                          Delete
                        </Button>
                      </div>
                    ) : null}
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {r.permissions.length === 0 ? <span className="text-xs text-fg-subtle">No permissions</span> : null}
                    {r.permissions.map((p) => (
                      <span key={p} title={perms.find((x) => x.name === p)?.description} className="rounded border border-border bg-bg-subtle px-1.5 py-0.5 font-mono text-[11px] text-fg-muted">
                        {p}
                      </span>
                    ))}
                  </div>
                </Card>
              ))
            )}
            {operator ? (
              <>
                <RoleDialog app={app} perms={perms} role={editing} open={editing !== null || creating} onClose={() => (setEditing(null), setCreating(false))} />
                <ConfirmDialog
                  open={deleting !== null}
                  onClose={() => setDeleting(null)}
                  onConfirm={() => deleting && del.mutate(deleting)}
                  loading={del.isPending}
                  danger
                  title={`Delete ${deleting?.name ?? ""}?`}
                  description="A role someone holds cannot be deleted; revoke it from them first."
                  confirmLabel="Delete"
                />
              </>
            ) : null}
          </div>
        );
      }}
    </QueryView>
  );
}

export function RolesPage() {
  const { ep } = useApp();
  const { tid, operator } = useCurrentTenant();
  const apps = useQuery({ queryKey: keys.apps, queryFn: ep.apps, staleTime: 300_000 });
  const tenantApps = useQuery({ queryKey: keys.tenantApps(tid), queryFn: () => ep.tenantApps(tid) });
  const [selected, setSelected] = useState<string | null>(null);
  return (
    <>
      <PageHeader
        title="Roles"
        description={
          operator
            ? "Each app's roles and the permissions they grant. As an operator you can create and edit roles; changes apply to every organisation."
            : "Each app's roles and the permissions they grant. Grant roles to members under App access."
        }
      />
      <QueryView query={apps}>
        {(all) => {
          if (all.length === 0) return <EmptyState icon={<ShieldCheck />} title="No apps registered" />;
          const enabled = new Set((tenantApps.data ?? []).filter((t) => t.status === "enabled").map((t) => t.app));
          const sorted = [...all].sort((a, b) => Number(enabled.has(b.slug)) - Number(enabled.has(a.slug)) || a.name.localeCompare(b.name));
          const current = sorted.find((a) => a.slug === selected) ?? sorted[0]!;
          return (
            <>
              <div role="tablist" aria-label="Apps" className="mb-5 flex gap-1 overflow-x-auto border-b border-border">
                {sorted.map((a) => (
                  <button
                    key={a.slug}
                    role="tab"
                    aria-selected={a.slug === current.slug}
                    onClick={() => setSelected(a.slug)}
                    className={cx(
                      "-mb-px flex h-9 items-center gap-1.5 border-b-2 px-3 text-[13px] whitespace-nowrap",
                      a.slug === current.slug ? "border-accent font-medium text-fg" : "border-transparent text-fg-muted hover:text-fg",
                    )}
                  >
                    {a.name}
                    {!enabled.has(a.slug) ? <span className="text-[11px] text-fg-subtle">(off)</span> : null}
                  </button>
                ))}
              </div>
              <AppRoles key={current.slug} app={current} />
            </>
          );
        }}
      </QueryView>
    </>
  );
}
