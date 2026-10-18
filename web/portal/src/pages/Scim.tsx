import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, KeyRound, Plus, RefreshCw } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { Card, PageHeader, QueryView, errorText, formatDate } from "../app/states";
import type { ScimTokenWithSecret } from "../lib/types";
import { Button, ConfirmDialog, Dialog, EmptyState, Field, Input, Select, Table, Td, Th, THead, Tr, useToast } from "../ui";

function copy(text: string, toast: ReturnType<typeof useToast>, what: string) {
  void navigator.clipboard?.writeText(text).then(() => toast.success(`${what} copied`));
}

export function ScimPage() {
  const { ep } = useApp();
  const { tid, canManage, isOwner } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const [tokenName, setTokenName] = useState<string | null>(null);
  const [created, setCreated] = useState<ScimTokenWithSecret | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [mapping, setMapping] = useState<{ group: string; app: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const tokens = useQuery({ queryKey: keys.scimTokens(tid), queryFn: () => ep.scimTokens(tid), enabled: isOwner });
  const mappings = useQuery({ queryKey: keys.groupMappings(tid), queryFn: () => ep.groupMappings(tid), enabled: canManage });
  const apps = useQuery({ queryKey: keys.tenantApps(tid), queryFn: () => ep.tenantApps(tid), enabled: canManage });
  const roles = useQuery({ queryKey: keys.roles(mapping?.app ?? ""), queryFn: () => ep.roles(mapping!.app), enabled: !!mapping?.app });

  const createToken = useMutation({
    mutationFn: (name: string) => ep.createScimToken(tid, name),
    onSuccess: (t) => {
      void qc.invalidateQueries({ queryKey: keys.scimTokens(tid) });
      setTokenName(null);
      setCreated(t);
    },
    onError: (e) => setError(errorText(e)),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => ep.revokeScimToken(tid, id),
    onSuccess: () => {
      setRevoking(null);
      void qc.invalidateQueries({ queryKey: keys.scimTokens(tid) });
      toast.success("Token revoked");
    },
    onError: (e) => toast.error("Couldn't revoke", errorText(e)),
  });
  const addMapping = useMutation({
    mutationFn: () => ep.createGroupMapping(tid, mapping!),
    onSuccess: () => {
      setMapping(null);
      void qc.invalidateQueries({ queryKey: keys.groupMappings(tid) });
      void qc.invalidateQueries({ queryKey: keys.grants(tid) });
      toast.success("Mapping added");
    },
    onError: (e) => setError(errorText(e)),
  });
  const delMapping = useMutation({
    mutationFn: (id: string) => ep.deleteGroupMapping(tid, id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.groupMappings(tid) });
      void qc.invalidateQueries({ queryKey: keys.grants(tid) });
    },
    onError: (e) => toast.error("Couldn't remove", errorText(e)),
  });

  return (
    <>
      <PageHeader title="Directory sync" description="Connect Okta or Microsoft Entra with SCIM so people and groups are provisioned automatically." />
      <h2 className="mb-2 text-sm font-semibold text-fg">SCIM tokens</h2>
      {!isOwner ? (
        <EmptyState icon={<KeyRound />} title="Owners only">Only owners can manage SCIM tokens.</EmptyState>
      ) : (
        <QueryView query={tokens} forbidden="manage SCIM tokens">
          {(data) => (
            <div className="mb-8 flex flex-col gap-3">
              <Card className="flex flex-wrap items-center justify-between gap-2 p-3 text-[13px]">
                <span className="text-fg-muted">SCIM base URL</span>
                <span className="flex items-center gap-2">
                  <code className="text-xs">{data.scim_base_url}</code>
                  <Button size="sm" variant="ghost" aria-label="Copy base URL" icon={<Copy className="size-3.5" />} onClick={() => copy(data.scim_base_url, toast, "URL")} />
                </span>
              </Card>
              {data.items.length > 0 ? (
                <Table>
                  <THead>
                    <tr><Th>Name</Th><Th>Token</Th><Th className="hidden sm:table-cell">Last used</Th><Th className="w-24" aria-label="Actions" /></tr>
                  </THead>
                  <tbody>
                    {data.items.map((t) => (
                      <Tr key={t.id}>
                        <Td className="font-medium text-fg">{t.name}</Td>
                        <Td><code className="text-xs">{t.prefix}…</code></Td>
                        <Td className="hidden text-fg-muted sm:table-cell">{formatDate(t.last_used_at)}</Td>
                        <Td className="text-right"><Button size="sm" variant="ghost" onClick={() => setRevoking(t.id)}>Revoke</Button></Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              ) : null}
              <div><Button icon={<Plus className="size-3.5" />} onClick={() => { setError(""); setTokenName(""); }}>New token</Button></div>
            </div>
          )}
        </QueryView>
      )}

      <h2 className="mb-2 text-sm font-semibold text-fg">Group to role mappings</h2>
      <QueryView query={mappings} forbidden="manage group mappings">
        {(list) => (
          <div className="flex flex-col gap-3">
            {list.length === 0 ? (
              <EmptyState icon={<RefreshCw />} title="No mappings">Map an identity-provider group to an app role so its members get access automatically.</EmptyState>
            ) : (
              <Table>
                <THead><tr><Th>Group</Th><Th>App</Th><Th>Role</Th><Th className="w-24" aria-label="Actions" /></tr></THead>
                <tbody>
                  {list.map((m) => (
                    <Tr key={m.id}>
                      <Td className="font-medium text-fg">{m.group}</Td>
                      <Td>{m.app}</Td>
                      <Td>{m.role}</Td>
                      <Td className="text-right"><Button size="sm" variant="ghost" onClick={() => delMapping.mutate(m.id)}>Remove</Button></Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
            <div><Button icon={<Plus className="size-3.5" />} onClick={() => { setError(""); setMapping({ group: "", app: "", role: "" }); }}>New mapping</Button></div>
          </div>
        )}
      </QueryView>

      <Dialog
        open={tokenName !== null}
        onClose={() => setTokenName(null)}
        title="New SCIM token"
        description="Paste it into your identity provider. It is shown once."
        onSubmit={() => (tokenName?.trim() ? createToken.mutate(tokenName.trim()) : setError("Give the token a name."))}
        footer={<><Button onClick={() => setTokenName(null)}>Cancel</Button><Button type="submit" variant="primary" loading={createToken.isPending}>Create</Button></>}
      >
        <Field label="Name" error={error}>{(id) => <Input id={id} autoFocus value={tokenName ?? ""} onChange={(e) => setTokenName(e.target.value)} placeholder="e.g. Okta production" />}</Field>
      </Dialog>
      <Dialog open={created !== null} onClose={() => setCreated(null)} title="Copy your token" description="You won't be able to see it again." footer={<Button variant="primary" onClick={() => setCreated(null)}>Done</Button>}>
        <div className="flex gap-2">
          <Input readOnly aria-label="SCIM token" value={created?.token ?? ""} className="font-mono" />
          <Button aria-label="Copy token" icon={<Copy className="size-3.5" />} onClick={() => copy(created?.token ?? "", toast, "Token")} />
        </div>
      </Dialog>
      <Dialog
        open={mapping !== null}
        onClose={() => setMapping(null)}
        title="Map a group to a role"
        onSubmit={() => (mapping && mapping.group.trim() && mapping.app && mapping.role ? addMapping.mutate() : setError("Fill in group, app and role."))}
        footer={<><Button onClick={() => setMapping(null)}>Cancel</Button><Button type="submit" variant="primary" loading={addMapping.isPending}>Add</Button></>}
      >
        <Field label="Group name" hint="Matches the SCIM group's display name, ignoring case." error={error}>
          {(id) => <Input id={id} autoFocus value={mapping?.group ?? ""} onChange={(e) => setMapping((m) => m && { ...m, group: e.target.value })} />}
        </Field>
        <Field label="App">
          {(id) => (
            <Select id={id} value={mapping?.app ?? ""} onChange={(e) => setMapping((m) => m && { ...m, app: e.target.value, role: "" })}>
              <option value="">Choose…</option>
              {(apps.data ?? []).map((a) => <option key={a.app} value={a.app}>{a.app}</option>)}
            </Select>
          )}
        </Field>
        <Field label="Role">
          {(id) => (
            <Select id={id} value={mapping?.role ?? ""} onChange={(e) => setMapping((m) => m && { ...m, role: e.target.value })} disabled={!mapping?.app}>
              <option value="">Choose…</option>
              {(roles.data ?? []).map((r) => <option key={r.name} value={r.name}>{r.name}</option>)}
            </Select>
          )}
        </Field>
      </Dialog>
      <ConfirmDialog open={revoking !== null} onClose={() => setRevoking(null)} onConfirm={() => revoking && revoke.mutate(revoking)} loading={revoke.isPending} danger title="Revoke this token?" description="The identity provider using it can no longer sync." confirmLabel="Revoke" />
    </>
  );
}
