import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Copy, KeyRound, Plus } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { PageHeader, QueryView, errorText, formatDate } from "../app/states";
import type { Agent, AgentWithSecret } from "../lib/types";
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Input, Select, Table, Td, Th, THead, Tr, useToast } from "../ui";

function SecretDialog({ agent, onClose }: { agent: AgentWithSecret | null; onClose: () => void }) {
  const toast = useToast();
  return (
    <Dialog
      open={agent !== null}
      onClose={onClose}
      title={`Credentials for ${agent?.name ?? ""}`}
      description="Copy the secret now. It is shown once and cannot be retrieved later; rotate it if lost."
      footer={<Button variant="primary" onClick={onClose}>Done</Button>}
    >
      <Field label="Client ID">{(id) => <Input id={id} readOnly value={agent?.client_id ?? ""} />}</Field>
      <Field label="Client secret" hint={agent?.token_endpoint ? `Token endpoint: ${agent.token_endpoint}` : undefined}>
        {(id) => (
          <div className="flex gap-2">
            <Input id={id} readOnly value={agent?.client_secret ?? ""} className="font-mono" />
            <Button
              aria-label="Copy secret"
              icon={<Copy className="size-3.5" />}
              onClick={() => void navigator.clipboard?.writeText(agent?.client_secret ?? "").then(() => toast.success("Secret copied"))}
            />
          </div>
        )}
      </Field>
    </Dialog>
  );
}

function CreateDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (a: AgentWithSecret) => void }) {
  const { ep } = useApp();
  const { tid } = useCurrentTenant();
  const qc = useQueryClient();
  const [kind, setKind] = useState<"service" | "agent">("agent");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const create = useMutation({
    mutationFn: () => ep.createAgent(tid, { kind, name: name.trim(), ...(description.trim() ? { description: description.trim() } : {}) }),
    onSuccess: (a) => {
      void qc.invalidateQueries({ queryKey: keys.agents(tid) });
      setName("");
      setDescription("");
      onClose();
      onCreated(a);
    },
    onError: (e) => setError(errorText(e)),
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="New service account or agent"
      description="It becomes a member of this organisation. Give it app roles afterwards under App access."
      onSubmit={() => {
        setError("");
        if (!name.trim()) return setError("Give it a name.");
        create.mutate();
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>Create</Button>
        </>
      }
    >
      <Field label="Type">
        {(id) => (
          <Select id={id} value={kind} onChange={(e) => setKind(e.target.value as "service" | "agent")}>
            <option value="agent">AI agent</option>
            <option value="service">Service account</option>
          </Select>
        )}
      </Field>
      <Field label="Name">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus />}</Field>
      <Field label="Description">{(id) => <Input id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
      {error ? <p className="text-xs text-danger">{error}</p> : null}
    </Dialog>
  );
}

export function AgentsPage() {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<AgentWithSecret | null>(null);
  const [deleting, setDeleting] = useState<Agent | null>(null);
  const agents = useQuery({ queryKey: keys.agents(tid), queryFn: () => ep.agents(tid), enabled: canManage });
  const refresh = () => qc.invalidateQueries({ queryKey: keys.agents(tid) });
  const toggle = useMutation({
    mutationFn: (a: Agent) => ep.setAgentStatus(tid, a.id, a.status === "active" ? "deactivated" : "active", a.version),
    onSuccess: (a) => {
      void refresh();
      toast.success(a.status === "active" ? `${a.name} reactivated` : `${a.name} deactivated`, a.status === "active" ? undefined : "Its tokens are refused straight away.");
    },
    onError: (e) => toast.error("Couldn't change status", errorText(e)),
  });
  const rotate = useMutation({
    mutationFn: (a: Agent) => ep.rotateAgentSecret(tid, a.id),
    onSuccess: (a) => {
      void refresh();
      setSecret(a);
    },
    onError: (e) => toast.error("Couldn't rotate", errorText(e)),
  });
  const remove = useMutation({
    mutationFn: (a: Agent) => ep.deleteAgent(tid, a.id),
    onSuccess: (_r, a) => {
      setDeleting(null);
      void refresh();
      toast.success(`${a.name} deleted`);
    },
    onError: (e) => toast.error("Couldn't delete", errorText(e)),
  });

  return (
    <>
      <PageHeader
        title="Agents"
        description="Service accounts and AI agents that call apps on their own or on behalf of people."
        actions={canManage ? <Button variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setCreating(true)}>New agent</Button> : undefined}
      />
      <QueryView query={agents} forbidden="manage agents">
        {(list) =>
          list.length === 0 ? (
            <EmptyState icon={<Bot />} title="No agents yet">Create one to give a script or an AI agent its own identity and audit trail.</EmptyState>
          ) : (
            <Table>
              <THead>
                <tr>
                  <Th>Name</Th>
                  <Th className="hidden sm:table-cell">Roles</Th>
                  <Th>Status</Th>
                  <Th className="hidden md:table-cell">Secret rotated</Th>
                  <Th className="w-56" aria-label="Actions" />
                </tr>
              </THead>
              <tbody>
                {list.map((a) => (
                  <Tr key={a.id}>
                    <Td>
                      <div className="flex items-center gap-1.5 font-medium text-fg">
                        {a.name}
                        <Badge>{a.kind === "agent" ? "agent" : "service"}</Badge>
                      </div>
                      <div className="truncate font-mono text-xs text-fg-muted">{a.client_id}</div>
                    </Td>
                    <Td className="hidden sm:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {a.grants.filter((g) => g.status === "active").map((g) => <Badge key={g.id}>{g.app}: {g.role}</Badge>)}
                      </div>
                    </Td>
                    <Td><Badge tone={a.status === "active" ? "success" : "warning"}>{a.status}</Badge></Td>
                    <Td className="hidden text-fg-muted md:table-cell">{formatDate(a.secret_rotated_at)}</Td>
                    <Td className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} loading={rotate.isPending && rotate.variables?.id === a.id} onClick={() => rotate.mutate(a)}>
                          Rotate
                        </Button>
                        <Button size="sm" variant="ghost" loading={toggle.isPending && toggle.variables?.id === a.id} onClick={() => toggle.mutate(a)}>
                          {a.status === "active" ? "Deactivate" : "Reactivate"}
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setDeleting(a)}>Delete</Button>
                      </div>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )
        }
      </QueryView>
      <CreateDialog open={creating} onClose={() => setCreating(false)} onCreated={setSecret} />
      <SecretDialog agent={secret} onClose={() => setSecret(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        loading={remove.isPending}
        danger
        title={`Delete ${deleting?.name ?? ""}?`}
        description="Its credentials stop working and its app roles are revoked. Audit history is kept."
        confirmLabel="Delete"
      />
    </>
  );
}
