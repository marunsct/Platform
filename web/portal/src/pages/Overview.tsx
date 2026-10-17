import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AppWindow, FolderKanban, Mail, Pencil, Users } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { Card, PageHeader, QueryView, errorText, formatDate } from "../app/states";
import { Badge, Button, Dialog, Field, Input, Skeleton, useToast } from "../ui";

function Stat({ label, value, to, tid, icon: Icon }: { label: string; value: number | string | undefined; to: string; tid: string; icon: typeof Users }) {
  return (
    <Link to={to} params={{ tid } as never} className="group rounded-md border border-border bg-bg-elevated p-4 transition-colors hover:border-border-strong">
      <div className="flex items-center gap-2 text-xs text-fg-muted">
        <Icon className="size-3.5" aria-hidden /> {label}
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-tight text-fg tabular-nums">{value ?? <Skeleton className="h-7 w-10" />}</div>
    </Link>
  );
}

export function OverviewPage() {
  const { ep } = useApp();
  const { tid, canManage, role } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const tenant = useQuery({ queryKey: keys.tenant(tid), queryFn: () => ep.tenant(tid) });
  const members = useQuery({ queryKey: keys.members(tid), queryFn: () => ep.members(tid) });
  const apps = useQuery({ queryKey: keys.tenantApps(tid), queryFn: () => ep.tenantApps(tid) });
  const workspaces = useQuery({ queryKey: keys.workspaces(tid), queryFn: () => ep.workspaces(tid) });
  const invitations = useQuery({ queryKey: keys.invitations(tid), queryFn: () => ep.invitations(tid), enabled: canManage });
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState("");
  const rename = useMutation({
    mutationFn: () => ep.renameTenant(tid, name.trim(), tenant.data!.version),
    onSuccess: (t) => {
      qc.setQueryData(keys.tenant(tid), t);
      void qc.invalidateQueries({ queryKey: keys.tenants });
      setRenaming(false);
      toast.success("Organisation renamed");
    },
    onError: (e) => toast.error("Couldn't rename", errorText(e)),
  });

  return (
    <QueryView query={tenant} forbidden="see this organisation">
      {(t) => (
        <>
          <PageHeader
            title={t.name}
            description={
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{t.slug}</span>
                <Badge tone={t.status === "active" ? "success" : "warning"}>{t.status}</Badge>
                {t.plan ? <Badge>{t.plan}</Badge> : null}
                {role ? <Badge tone="accent">you: {role}</Badge> : null}
              </span>
            }
            actions={
              canManage ? (
                <Button
                  icon={<Pencil className="size-3.5" />}
                  onClick={() => {
                    setName(t.name);
                    setRenaming(true);
                  }}
                >
                  Rename
                </Button>
              ) : undefined
            }
          />
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat tid={tid} to="/t/$tid/members" icon={Users} label="Members" value={members.data?.filter((m) => m.status === "active").length} />
            <Stat tid={tid} to="/t/$tid/invitations" icon={Mail} label="Pending invitations" value={canManage ? invitations.data?.filter((i) => i.state === "pending").length : "—"} />
            <Stat tid={tid} to="/t/$tid/apps" icon={AppWindow} label="Apps enabled" value={apps.data?.filter((a) => a.status === "enabled").length} />
            <Stat tid={tid} to="/t/$tid/workspaces" icon={FolderKanban} label="Workspaces" value={workspaces.data?.filter((w) => w.status === "active").length} />
          </div>
          <Card className="mt-6 divide-y divide-border">
            {[
              ["Kind", t.kind],
              ["Default data placement", t.data_mode_default],
              ["Created", formatDate(t.created_at)],
              ["Organisation id", <span className="font-mono text-xs select-all">{t.id}</span>],
            ].map(([k, v]) => (
              <div key={String(k)} className="flex items-center justify-between gap-4 px-4 py-3">
                <span className="text-fg-muted">{k}</span>
                <span className="text-right text-fg">{v}</span>
              </div>
            ))}
          </Card>
          <Dialog
            open={renaming}
            onClose={() => setRenaming(false)}
            title="Rename organisation"
            onSubmit={() => name.trim() && rename.mutate()}
            footer={
              <>
                <Button onClick={() => setRenaming(false)}>Cancel</Button>
                <Button type="submit" variant="primary" loading={rename.isPending} disabled={!name.trim()}>
                  Save
                </Button>
              </>
            }
          >
            <Field label="Name">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={200} />}</Field>
          </Dialog>
        </>
      )}
    </QueryView>
  );
}
