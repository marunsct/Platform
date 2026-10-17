import { useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Mail, Send, UserPlus } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { NeedAdmin, PageHeader, QueryView, errorText, formatDate, relative } from "../app/states";
import { TENANT_ROLES, type Invitation, type InvitationState, type InvitedRole, type TenantRole } from "../lib/types";
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Input, Select, Table, Td, Th, THead, Tr, useToast, type Tone } from "../ui";

const stateTone: Record<InvitationState, Tone> = { pending: "accent", accepted: "success", revoked: "neutral", expired: "warning" };

export function StateBadge({ state }: { state: InvitationState }) {
  return <Badge tone={stateTone[state] ?? "neutral"}>{state}</Badge>;
}

function useEnabledAppRoles(tid: string, enabled: boolean) {
  const { ep } = useApp();
  const tenantApps = useQuery({ queryKey: keys.tenantApps(tid), queryFn: () => ep.tenantApps(tid), enabled });
  const apps = useQuery({ queryKey: keys.apps, queryFn: ep.apps, enabled, staleTime: 300_000 });
  const slugs = (tenantApps.data ?? []).filter((a) => a.status === "enabled").map((a) => a.app);
  const roles = useQueries({ queries: slugs.map((s) => ({ queryKey: keys.roles(s), queryFn: () => ep.roles(s), staleTime: 60_000 })) });
  return slugs.map((slug, i) => ({
    slug,
    name: apps.data?.find((a) => a.slug === slug)?.name ?? slug,
    roles: roles[i]?.data ?? [],
  }));
}

function InviteDialog({ open, onClose, onSent }: { open: boolean; onClose: () => void; onSent: (inv: Invitation) => void }) {
  const { ep } = useApp();
  const { tid, isOwner } = useCurrentTenant();
  const qc = useQueryClient();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<TenantRole>("member");
  const [appRoles, setAppRoles] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const apps = useEnabledAppRoles(tid, open);
  const invite = useMutation({
    mutationFn: () => {
      const app_roles: InvitedRole[] = Object.entries(appRoles)
        .filter(([, r]) => r)
        .map(([app, r]) => ({ app, role: r }));
      return ep.invite(tid, { email: email.trim(), tenant_role: role, app_roles });
    },
    onSuccess: (inv) => {
      void qc.invalidateQueries({ queryKey: keys.invitations(tid) });
      setEmail("");
      setAppRoles({});
      setRole("member");
      onSent(inv);
    },
    onError: (e) => setError(errorText(e)),
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Invite someone"
      description="They get an email with a link to join. They sign in, or create an account, with this address."
      onSubmit={() => {
        setError("");
        if (!/^[^\s@]+@[^\s@]+$/.test(email.trim())) return setError("Enter an email address.");
        invite.mutate();
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={invite.isPending} icon={<Send className="size-3.5" />}>
            Send invitation
          </Button>
        </>
      }
    >
      <Field label="Email" error={error || undefined}>
        {(id) => <Input id={id} type="email" autoComplete="off" autoFocus placeholder="name@company.com" value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={!!error || undefined} />}
      </Field>
      <Field label="Organisation role" hint="Owners and admins manage members, invitations and apps.">
        {(id) => (
          <Select id={id} value={role} onChange={(e) => setRole(e.target.value as TenantRole)}>
            {TENANT_ROLES.map((r) => (
              <option key={r} value={r} disabled={r === "owner" && !isOwner}>
                {r}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {apps.length > 0 ? (
        <fieldset className="flex flex-col gap-3">
          <legend className="mb-2 text-xs font-medium text-fg">App roles</legend>
          {apps.map((a) => (
            <div key={a.slug} className="grid grid-cols-[1fr_1.3fr] items-center gap-3">
              <span className="truncate text-[13px] text-fg-muted">{a.name}</span>
              <Select aria-label={`Role in ${a.name}`} value={appRoles[a.slug] ?? ""} onChange={(e) => setAppRoles({ ...appRoles, [a.slug]: e.target.value })}>
                <option value="">Default role{a.roles.find((r) => r.is_default) ? ` (${a.roles.find((r) => r.is_default)!.name})` : ""}</option>
                {a.roles.map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.name}
                  </option>
                ))}
              </Select>
            </div>
          ))}
        </fieldset>
      ) : null}
    </Dialog>
  );
}

function LinkDialog({ inv, onClose }: { inv: Invitation | null; onClose: () => void }) {
  const toast = useToast();
  return (
    <Dialog
      open={inv !== null}
      onClose={onClose}
      title="Invitation sent"
      description={inv ? `We emailed ${inv.deliver_to ?? inv.email}. If email is not set up on this server, send them this link yourself; it is shown only now.` : undefined}
      footer={<Button variant="primary" onClick={onClose}>Done</Button>}
    >
      {inv?.accept_url ? (
        <div className="flex gap-2">
          <Input readOnly value={inv.accept_url} aria-label="Invitation link" onFocus={(e) => e.currentTarget.select()} className="font-mono text-xs" />
          <Button
            icon={<Copy className="size-3.5" />}
            onClick={() =>
              navigator.clipboard.writeText(inv.accept_url!).then(
                () => toast.success("Link copied"),
                () => toast.error("Couldn't copy", "Select the link and copy it."),
              )
            }
          >
            Copy
          </Button>
        </div>
      ) : null}
    </Dialog>
  );
}

export function InvitationsPage() {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const search = useSearch({ strict: false }) as { invite?: boolean };
  const [sent, setSent] = useState<Invitation | null>(null);
  const [revoking, setRevoking] = useState<Invitation | null>(null);
  const inviting = !!search.invite;
  const setInviting = (v: boolean) => void navigate({ to: "/t/$tid/invitations", params: { tid }, search: v ? { invite: true } : {}, replace: true });
  const invitations = useQuery({ queryKey: keys.invitations(tid), queryFn: () => ep.invitations(tid), enabled: canManage });

  const resend = useMutation({
    mutationFn: (inv: Invitation) => ep.resendInvitation(tid, inv.id),
    onSuccess: (inv) => {
      void qc.invalidateQueries({ queryKey: keys.invitations(tid) });
      setSent(inv);
    },
    onError: (e) => toast.error("Couldn't resend", errorText(e)),
  });
  const revoke = useMutation({
    mutationFn: (inv: Invitation) => ep.revokeInvitation(tid, inv.id),
    onSuccess: (_r, inv) => {
      setRevoking(null);
      qc.setQueryData<Invitation[]>(keys.invitations(tid), (xs) => xs?.map((x) => (x.id === inv.id ? { ...x, state: "revoked" } : x)));
      toast.success(`Invitation for ${inv.email} revoked`);
    },
    onError: (e) => toast.error("Couldn't revoke", errorText(e)),
  });

  return (
    <>
      <PageHeader
        title="Invitations"
        description="Invite people by email with their organisation role and app roles. Links expire after 7 days."
        actions={
          canManage ? (
            <Button variant="primary" icon={<UserPlus className="size-3.5" />} onClick={() => setInviting(true)}>
              Invite people
            </Button>
          ) : undefined
        }
      />
      {!canManage ? (
        <NeedAdmin what="see and send invitations" />
      ) : (
        <QueryView query={invitations} forbidden="see and send invitations">
          {(list) =>
            list.length === 0 ? (
              <EmptyState icon={<Mail />} title="No invitations yet" action={<Button variant="primary" onClick={() => setInviting(true)}>Invite people</Button>}>
                Invited people show here until they join, and afterwards as accepted.
              </EmptyState>
            ) : (
              <Table>
                <THead>
                  <tr>
                    <Th>Email</Th>
                    <Th>Roles</Th>
                    <Th>State</Th>
                    <Th className="hidden md:table-cell">Expires</Th>
                    <Th className="w-40" aria-label="Actions" />
                  </tr>
                </THead>
                <tbody>
                  {list.map((inv) => (
                    <Tr key={inv.id}>
                      <Td>
                        <div className="font-medium text-fg">{inv.email}</div>
                        <div className="text-xs text-fg-muted">
                          sent {inv.sent_count}× · {formatDate(inv.created_at)}
                          {inv.deliver_to ? ` · to ${inv.deliver_to}` : ""}
                        </div>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          <Badge tone={inv.tenant_role === "member" ? "neutral" : "accent"}>{inv.tenant_role}</Badge>
                          {inv.app_roles.map((r) => (
                            <Badge key={r.app + r.role}>
                              {r.app}: {r.role}
                            </Badge>
                          ))}
                        </div>
                      </Td>
                      <Td>
                        <StateBadge state={inv.state} />
                      </Td>
                      <Td className="hidden text-fg-muted md:table-cell">{inv.state === "pending" ? relative(inv.expires_at) : "—"}</Td>
                      <Td className="text-right whitespace-nowrap">
                        {inv.state === "pending" || inv.state === "expired" ? (
                          <Button size="sm" variant="ghost" loading={resend.isPending && resend.variables?.id === inv.id} onClick={() => resend.mutate(inv)}>
                            Resend
                          </Button>
                        ) : null}
                        {inv.state === "pending" ? (
                          <Button size="sm" variant="ghost" onClick={() => setRevoking(inv)}>
                            Revoke
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
      )}
      {canManage ? (
        <InviteDialog
          open={inviting}
          onClose={() => setInviting(false)}
          onSent={(inv) => {
            setInviting(false);
            setSent(inv);
          }}
        />
      ) : null}
      <LinkDialog inv={sent} onClose={() => setSent(null)} />
      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking)}
        loading={revoke.isPending}
        danger
        title="Revoke this invitation?"
        description={`The link sent to ${revoking?.email ?? ""} stops working. You can invite them again later.`}
        confirmLabel="Revoke"
      />
    </>
  );
}
