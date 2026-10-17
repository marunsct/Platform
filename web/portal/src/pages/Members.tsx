import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, UserPlus, Users } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { Avatar, PageHeader, QueryView, errorText, formatDate } from "../app/states";
import { TENANT_ROLES, type Member, type TenantRole } from "../lib/types";
import { Badge, Button, ConfirmDialog, EmptyState, Input, Select, Table, Td, Th, THead, Tr, useToast } from "../ui";

export function memberName(m: Pick<Member, "display_name" | "email" | "user_id">): string {
  return m.display_name || m.email || m.user_id.slice(0, 8);
}

export function MembersPage() {
  const { ep } = useApp();
  const { tid, canManage, isOwner, meId } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [removing, setRemoving] = useState<Member | null>(null);
  const members = useQuery({ queryKey: keys.members(tid), queryFn: () => ep.members(tid) });
  const grants = useQuery({ queryKey: keys.grants(tid), queryFn: () => ep.grants(tid) });

  const rolesByUser = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const g of grants.data ?? []) {
      if (g.status !== "active") continue;
      m.set(g.subject_id, [...(m.get(g.subject_id) ?? []), `${g.app}: ${g.role}`]);
    }
    return m;
  }, [grants.data]);

  const changeRole = useMutation({
    mutationFn: ({ uid, role }: { uid: string; role: TenantRole }) => ep.setMemberRole(tid, uid, role),
    onMutate: async ({ uid, role }) => {
      await qc.cancelQueries({ queryKey: keys.members(tid) });
      const prev = qc.getQueryData<Member[]>(keys.members(tid));
      qc.setQueryData<Member[]>(keys.members(tid), (ms) => ms?.map((m) => (m.user_id === uid ? { ...m, tenant_role: role } : m)));
      return { prev };
    },
    onError: (e, _v, ctx) => {
      qc.setQueryData(keys.members(tid), ctx?.prev);
      toast.error("Couldn't change the role", errorText(e));
    },
    onSuccess: (m) => toast.success(`${memberName(m)} is now ${m.tenant_role}`),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.members(tid) });
      void qc.invalidateQueries({ queryKey: keys.tenants });
    },
  });

  const remove = useMutation({
    mutationFn: (m: Member) => ep.removeMember(tid, m.user_id),
    onSuccess: (_r, m) => {
      setRemoving(null);
      qc.setQueryData<Member[]>(keys.members(tid), (ms) => ms?.filter((x) => x.user_id !== m.user_id));
      void qc.invalidateQueries({ queryKey: keys.grants(tid) });
      toast.success(m.user_id === meId ? "You left the organisation" : `${memberName(m)} was removed`);
      if (m.user_id === meId) void qc.invalidateQueries({ queryKey: keys.tenants });
    },
    onError: (e) => toast.error("Couldn't remove", errorText(e)),
  });

  return (
    <>
      <PageHeader
        title="Members"
        description="People in this organisation and their organisation role. App roles are managed under App access."
        actions={
          canManage ? (
            <Button variant="primary" icon={<UserPlus className="size-3.5" />} onClick={() => void navigate({ to: "/t/$tid/invitations", params: { tid }, search: { invite: true } })}>
              Invite people
            </Button>
          ) : undefined
        }
      />
      <QueryView query={members} forbidden="see the member list">
        {(list) => {
          const needle = q.trim().toLowerCase();
          const shown = list.filter((m) => !needle || `${m.display_name ?? ""} ${m.email ?? ""}`.toLowerCase().includes(needle));
          if (list.length === 0) return <EmptyState icon={<Users />} title="No members yet" />;
          return (
            <>
              <div className="relative mb-3 max-w-xs">
                <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-subtle" aria-hidden />
                <Input aria-label="Search members" placeholder="Search by name or email" value={q} onChange={(e) => setQ(e.target.value)} className="pl-8" />
              </div>
              {shown.length === 0 ? (
                <EmptyState icon={<Search />} title="No one matches">
                  Try another name or email.
                </EmptyState>
              ) : (
                <Table>
                  <THead>
                    <tr>
                      <Th>Member</Th>
                      <Th className="w-36">Role</Th>
                      <Th className="hidden lg:table-cell">App roles</Th>
                      <Th className="hidden sm:table-cell">Joined</Th>
                      <Th className="w-24" aria-label="Actions" />
                    </tr>
                  </THead>
                  <tbody>
                    {shown.map((m) => {
                      const self = m.user_id === meId;
                      const locked = !canManage || (m.tenant_role === "owner" && !isOwner);
                      return (
                        <Tr key={m.user_id}>
                          <Td>
                            <div className="flex items-center gap-2.5">
                              <Avatar name={memberName(m)} />
                              <div className="min-w-0">
                                <div className="flex items-center gap-1.5 truncate font-medium text-fg">
                                  {memberName(m)}
                                  {self ? <Badge>you</Badge> : null}
                                  {m.status !== "active" ? <Badge tone="warning">{m.status}</Badge> : null}
                                </div>
                                {m.display_name && m.email ? <div className="truncate text-xs text-fg-muted">{m.email}</div> : null}
                              </div>
                            </div>
                          </Td>
                          <Td>
                            {locked ? (
                              <Badge tone={m.tenant_role === "owner" ? "accent" : "neutral"}>{m.tenant_role}</Badge>
                            ) : (
                              <Select
                                aria-label={`Role of ${memberName(m)}`}
                                value={m.tenant_role}
                                onChange={(e) => changeRole.mutate({ uid: m.user_id, role: e.target.value as TenantRole })}
                              >
                                {TENANT_ROLES.map((r) => (
                                  <option key={r} value={r} disabled={r === "owner" && !isOwner}>
                                    {r}
                                  </option>
                                ))}
                              </Select>
                            )}
                          </Td>
                          <Td className="hidden lg:table-cell">
                            <div className="flex flex-wrap gap-1">
                              {(rolesByUser.get(m.user_id) ?? []).map((r) => (
                                <Badge key={r}>{r}</Badge>
                              ))}
                              {!rolesByUser.get(m.user_id) ? <span className="text-xs text-fg-subtle">—</span> : null}
                            </div>
                          </Td>
                          <Td className="hidden text-fg-muted sm:table-cell">{formatDate(m.joined_at)}</Td>
                          <Td className="text-right">
                            {self || !locked ? (
                              <Button size="sm" variant="ghost" onClick={() => setRemoving(m)}>
                                {self ? "Leave" : "Remove"}
                              </Button>
                            ) : null}
                          </Td>
                        </Tr>
                      );
                    })}
                  </tbody>
                </Table>
              )}
            </>
          );
        }}
      </QueryView>
      <ConfirmDialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        onConfirm={() => removing && remove.mutate(removing)}
        loading={remove.isPending}
        danger
        title={removing?.user_id === meId ? "Leave this organisation?" : `Remove ${removing ? memberName(removing) : ""}?`}
        description={
          removing?.user_id === meId
            ? "You lose access to its apps straight away. An admin can invite you again."
            : "They lose access to this organisation's apps at their next sign-in or token refresh. Their app roles here are revoked."
        }
        confirmLabel={removing?.user_id === meId ? "Leave" : "Remove"}
      />
    </>
  );
}
