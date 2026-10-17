import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderKanban, Plus } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { PageHeader, QueryView, errorText, formatDate } from "../app/states";
import type { Workspace } from "../lib/types";
import { Badge, Button, Dialog, EmptyState, Field, Input, Table, Td, Th, THead, Tr, useToast } from "../ui";

function NameDialog({ open, title, initial, submitLabel, onClose, onSave, saving, error }: { open: boolean; title: string; initial: string; submitLabel: string; onClose: () => void; onSave: (name: string) => void; saving: boolean; error?: string }) {
  const [name, setName] = useState(initial);
  const [last, setLast] = useState(initial);
  if (initial !== last) {
    setLast(initial);
    setName(initial);
  }
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      onSubmit={() => name.trim() && onSave(name.trim())}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={saving} disabled={!name.trim()}>
            {submitLabel}
          </Button>
        </>
      }
    >
      <Field label="Name" error={error}>
        {(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus maxLength={200} placeholder="e.g. Marketing" />}
      </Field>
    </Dialog>
  );
}

export function WorkspacesPage() {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const [renaming, setRenaming] = useState<Workspace | null>(null);
  const workspaces = useQuery({ queryKey: keys.workspaces(tid), queryFn: () => ep.workspaces(tid) });

  const create = useMutation({
    mutationFn: (name: string) => ep.createWorkspace(tid, name),
    onSuccess: (w) => {
      qc.setQueryData<Workspace[]>(keys.workspaces(tid), (ws) => [...(ws ?? []), w]);
      setCreating(false);
      toast.success(`Workspace ${w.name} created`);
    },
  });
  const rename = useMutation({
    mutationFn: ({ w, name }: { w: Workspace; name: string }) => ep.renameWorkspace(tid, w.id, name),
    onSuccess: (w) => {
      qc.setQueryData<Workspace[]>(keys.workspaces(tid), (ws) => ws?.map((x) => (x.id === w.id ? w : x)));
      setRenaming(null);
      toast.success("Workspace renamed");
    },
  });

  return (
    <>
      <PageHeader
        title="Workspaces"
        description="Workspaces divide an organisation's data in apps that support them. App roles can be granted per workspace."
        actions={
          canManage ? (
            <Button variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setCreating(true)}>
              New workspace
            </Button>
          ) : undefined
        }
      />
      <QueryView query={workspaces} forbidden="see workspaces">
        {(list) =>
          list.length === 0 ? (
            <EmptyState icon={<FolderKanban />} title="No workspaces yet" action={canManage ? <Button onClick={() => setCreating(true)}>New workspace</Button> : undefined} />
          ) : (
            <Table>
              <THead>
                <tr>
                  <Th>Name</Th>
                  <Th>Status</Th>
                  <Th className="hidden sm:table-cell">Updated</Th>
                  <Th className="w-24" aria-label="Actions" />
                </tr>
              </THead>
              <tbody>
                {list.map((w) => (
                  <Tr key={w.id}>
                    <Td>
                      <span className="font-medium text-fg">{w.name}</span> {w.is_default ? <Badge>default</Badge> : null}
                    </Td>
                    <Td>
                      <Badge tone={w.status === "active" ? "success" : "neutral"}>{w.status}</Badge>
                    </Td>
                    <Td className="hidden text-fg-muted sm:table-cell">{formatDate(w.updated_at)}</Td>
                    <Td className="text-right">
                      {canManage ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            rename.reset();
                            setRenaming(w);
                          }}
                        >
                          Rename
                        </Button>
                      ) : null}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )
        }
      </QueryView>
      <NameDialog
        open={creating}
        title="New workspace"
        initial=""
        submitLabel="Create"
        onClose={() => {
          setCreating(false);
          create.reset();
        }}
        onSave={(n) => create.mutate(n)}
        saving={create.isPending}
        error={create.error ? errorText(create.error) : undefined}
      />
      <NameDialog
        open={renaming !== null}
        title="Rename workspace"
        initial={renaming?.name ?? ""}
        submitLabel="Save"
        onClose={() => setRenaming(null)}
        onSave={(n) => renaming && rename.mutate({ w: renaming, name: n })}
        saving={rename.isPending}
        error={rename.error ? errorText(rename.error) : undefined}
      />
    </>
  );
}
