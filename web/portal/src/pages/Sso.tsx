import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Copy, Globe, KeyRound, Plus, RefreshCw } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { Card, PageHeader, QueryView, errorText, formatDate } from "../app/states";
import { ApiError } from "../lib/api";
import { TENANT_ROLES, type SSOInput, type SSOProtocol, type TenantRole } from "../lib/types";
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Input, Select, useToast } from "../ui";

function CopyValue({ label, value }: { label: string; value: string }) {
  const toast = useToast();
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-fg-muted">{label}</span>
      <span className="flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate rounded bg-bg-muted px-2 py-1 text-xs">{value}</code>
        <Button
          size="sm"
          variant="ghost"
          aria-label={`Copy ${label}`}
          icon={<Copy className="size-3.5" />}
          onClick={() => void navigator.clipboard?.writeText(value).then(() => toast.success(`${label} copied`))}
        />
      </span>
    </div>
  );
}

function DomainsSection() {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const [adding, setAdding] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [removing, setRemoving] = useState<string | null>(null);
  const domains = useQuery({ queryKey: keys.domains(tid), queryFn: () => ep.domains(tid), enabled: canManage });
  const refresh = () => qc.invalidateQueries({ queryKey: keys.domains(tid) });
  const add = useMutation({
    mutationFn: (d: string) => ep.addDomain(tid, d),
    onSuccess: () => {
      setAdding(null);
      void refresh();
    },
    onError: (e) => setError(errorText(e)),
  });
  const verify = useMutation({
    mutationFn: (d: string) => ep.verifyDomain(tid, d),
    onSuccess: (d) => {
      void refresh();
      if (d.verified) toast.success(`${d.domain} is verified`);
      else toast.error(`${d.domain} is not verified yet`, d.last_error ?? "The TXT record was not found. DNS changes can take a while.");
    },
    onError: (e) => toast.error("Couldn't check the domain", errorText(e)),
  });
  const remove = useMutation({
    mutationFn: (d: string) => ep.deleteDomain(tid, d),
    onSuccess: () => {
      setRemoving(null);
      void refresh();
    },
    onError: (e) => toast.error("Couldn't remove", errorText(e)),
  });
  return (
    <section className="mb-8">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-fg">Verified domains</h2>
        <Button icon={<Plus className="size-3.5" />} onClick={() => { setError(""); setAdding(""); }}>Add domain</Button>
      </div>
      <p className="mb-3 text-[13px] text-fg-muted">
        Sign-ins through your identity provider are accepted only for email addresses in domains you verify.
      </p>
      <QueryView query={domains} forbidden="manage domains">
        {(list) =>
          list.length === 0 ? (
            <EmptyState icon={<Globe />} title="No domains yet">Add the domain your people's email addresses use, then publish the TXT record we show.</EmptyState>
          ) : (
            <div className="flex flex-col gap-3">
              {list.map((d) => (
                <Card key={d.domain} className="p-4">
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 font-medium text-fg">
                      {d.domain}
                      {d.verified ? <Badge tone="success">verified</Badge> : <Badge tone="warning">not verified</Badge>}
                    </div>
                    <div className="flex gap-1">
                      {!d.verified ? (
                        <Button size="sm" icon={<RefreshCw className="size-3.5" />} loading={verify.isPending && verify.variables === d.domain} onClick={() => verify.mutate(d.domain)}>
                          Check now
                        </Button>
                      ) : null}
                      <Button size="sm" variant="ghost" onClick={() => setRemoving(d.domain)}>Remove</Button>
                    </div>
                  </div>
                  {d.verified ? (
                    <p className="flex items-center gap-1.5 text-[13px] text-fg-muted">
                      <CheckCircle2 className="size-3.5" aria-hidden /> Verified {formatDate(d.verified_at)}
                    </p>
                  ) : (
                    <div className="grid gap-2 sm:grid-cols-2">
                      <CopyValue label="TXT record name" value={d.record_name} />
                      <CopyValue label="TXT record value" value={d.record_value} />
                      {d.last_error ? <p className="text-xs text-danger sm:col-span-2">{d.last_error}</p> : null}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )
        }
      </QueryView>
      <Dialog
        open={adding !== null}
        onClose={() => setAdding(null)}
        title="Add a domain"
        description="You then publish a TXT record in its DNS to prove you control it."
        onSubmit={() => (adding?.trim() ? add.mutate(adding.trim().toLowerCase()) : setError("Enter a domain."))}
        footer={<><Button onClick={() => setAdding(null)}>Cancel</Button><Button type="submit" variant="primary" loading={add.isPending}>Add</Button></>}
      >
        <Field label="Domain" error={error}>{(id) => <Input id={id} autoFocus placeholder="acme.com" value={adding ?? ""} onChange={(e) => setAdding(e.target.value)} />}</Field>
      </Dialog>
      <ConfirmDialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        onConfirm={() => removing && remove.mutate(removing)}
        loading={remove.isPending}
        danger
        title={`Remove ${removing ?? ""}?`}
        description="Sign-ins through your identity provider stop being accepted for this domain."
        confirmLabel="Remove"
      />
    </section>
  );
}

const blank: SSOInput = { protocol: "oidc", display_name: "", discovery_url: "", client_id: "", client_secret: "", metadata_url: "", default_tenant_role: "member" };

function ConnectionSection() {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const qc = useQueryClient();
  const toast = useToast();
  const [form, setForm] = useState<SSOInput | null>(null);
  const [error, setError] = useState("");
  const [removing, setRemoving] = useState(false);
  const conn = useQuery({
    queryKey: keys.sso(tid),
    enabled: canManage,
    retry: (n, e) => !(e instanceof ApiError && e.notFound) && n < 2,
    queryFn: async () => {
      try {
        return await ep.sso(tid);
      } catch (e) {
        if (e instanceof ApiError && e.notFound) return null;
        throw e;
      }
    },
  });
  const create = useMutation({
    mutationFn: (body: SSOInput) => ep.createSSO(tid, body),
    onSuccess: () => {
      setForm(null);
      void qc.invalidateQueries({ queryKey: keys.sso(tid) });
      toast.success("Identity provider connected", "Finish the setup on your identity provider with the values shown.");
    },
    onError: (e) => setError(errorText(e)),
  });
  const remove = useMutation({
    mutationFn: () => ep.deleteSSO(tid),
    onSuccess: () => {
      setRemoving(false);
      void qc.invalidateQueries({ queryKey: keys.sso(tid) });
    },
    onError: (e) => toast.error("Couldn't disconnect", errorText(e)),
  });
  const set = (k: keyof SSOInput, v: string) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const submit = () => {
    if (!form) return;
    setError("");
    if (!form.display_name.trim()) return setError("Give the connection a name your people recognise.");
    const body: SSOInput = { protocol: form.protocol, display_name: form.display_name.trim(), default_tenant_role: form.default_tenant_role };
    if (form.protocol === "oidc") {
      if (!form.discovery_url?.trim() || !form.client_id?.trim() || !form.client_secret?.trim()) return setError("Issuer URL, client ID and client secret are required.");
      Object.assign(body, { discovery_url: form.discovery_url.trim(), client_id: form.client_id.trim(), client_secret: form.client_secret });
    } else {
      if (!form.metadata_url?.trim()) return setError("The identity provider's metadata URL is required.");
      body.metadata_url = form.metadata_url.trim();
    }
    create.mutate(body);
  };
  return (
    <section>
      <h2 className="mb-2 text-sm font-semibold text-fg">Identity provider</h2>
      <QueryView query={conn} forbidden="manage single sign-on">
        {(c) =>
          !c ? (
            <EmptyState
              icon={<KeyRound />}
              title="Not connected"
              action={<Button variant="primary" icon={<Plus className="size-3.5" />} onClick={() => { setError(""); setForm({ ...blank }); }}>Connect an identity provider</Button>}
            >
              Okta, Microsoft Entra ID, Google Workspace, JumpCloud or any OIDC or SAML provider.
            </EmptyState>
          ) : (
            <Card className="p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-medium text-fg">
                  {c.display_name}
                  <Badge>{c.protocol.toUpperCase()}</Badge>
                </div>
                <Button size="sm" variant="ghost" onClick={() => setRemoving(true)}>Disconnect</Button>
              </div>
              <p className="mb-3 text-[13px] text-fg-muted">
                Give these to your identity provider's administrator. New people join as <strong>{c.default_tenant_role}</strong>.
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                <CopyValue label={c.protocol === "saml" ? "Assertion consumer service URL" : "Redirect URI"} value={c.redirect_uri} />
                {c.entity_id ? <CopyValue label="Entity ID" value={c.entity_id} /> : null}
                {c.metadata_url ? <CopyValue label="Service provider metadata" value={c.metadata_url} /> : null}
                <CopyValue label="Sign-in hint (kc_idp_hint)" value={c.idp_hint} />
              </div>
            </Card>
          )
        }
      </QueryView>
      <Dialog
        open={form !== null}
        onClose={() => setForm(null)}
        title="Connect an identity provider"
        description="Verify your domains first: only their addresses can sign in through it."
        className="w-[min(520px,calc(100vw-32px))]"
        onSubmit={submit}
        footer={<><Button onClick={() => setForm(null)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Connect</Button></>}
      >
        <Field label="Protocol">
          {(id) => (
            <Select id={id} value={form?.protocol ?? "oidc"} onChange={(e) => set("protocol", e.target.value as SSOProtocol)}>
              <option value="oidc">OpenID Connect</option>
              <option value="saml">SAML 2.0</option>
            </Select>
          )}
        </Field>
        <Field label="Name shown on the sign-in page">{(id) => <Input id={id} autoFocus placeholder="Acme Okta" value={form?.display_name ?? ""} onChange={(e) => set("display_name", e.target.value)} />}</Field>
        {form?.protocol === "saml" ? (
          <Field label="Identity provider metadata URL" hint="Okta: Sign On tab → Metadata URL. Entra: App Federation Metadata Url.">
            {(id) => <Input id={id} placeholder="https://…/metadata" value={form.metadata_url ?? ""} onChange={(e) => set("metadata_url", e.target.value)} />}
          </Field>
        ) : (
          <>
            <Field label="Issuer URL" hint="Or its /.well-known/openid-configuration address.">
              {(id) => <Input id={id} placeholder="https://acme.okta.com" value={form?.discovery_url ?? ""} onChange={(e) => set("discovery_url", e.target.value)} />}
            </Field>
            <Field label="Client ID">{(id) => <Input id={id} value={form?.client_id ?? ""} onChange={(e) => set("client_id", e.target.value)} />}</Field>
            <Field label="Client secret" hint="Stored encrypted under your organisation's key; never shown again.">
              {(id) => <Input id={id} type="password" autoComplete="off" value={form?.client_secret ?? ""} onChange={(e) => set("client_secret", e.target.value)} />}
            </Field>
          </>
        )}
        <Field label="Role for people who join through it">
          {(id) => (
            <Select id={id} value={form?.default_tenant_role ?? "member"} onChange={(e) => set("default_tenant_role", e.target.value as TenantRole)}>
              {TENANT_ROLES.filter((r) => r !== "owner").map((r) => <option key={r} value={r}>{r}</option>)}
            </Select>
          )}
        </Field>
        {error ? <p className="text-xs text-danger">{error}</p> : null}
      </Dialog>
      <ConfirmDialog
        open={removing}
        onClose={() => setRemoving(false)}
        onConfirm={() => remove.mutate()}
        loading={remove.isPending}
        danger
        title="Disconnect the identity provider?"
        description="People who signed in through it keep their accounts but must use another sign-in method."
        confirmLabel="Disconnect"
      />
    </section>
  );
}

export function SsoPage() {
  return (
    <>
      <PageHeader title="Single sign-on" description="Let your people sign in with your company's identity provider." />
      <DomainsSection />
      <ConnectionSection />
    </>
  );
}
