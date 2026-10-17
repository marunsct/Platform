import { useState } from "react";
import { Navigate, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useTenants } from "../app/queries";
import { LoadingRows, PageHeader, QueryView, errorText } from "../app/states";
import { lastTenant } from "../app/theme";
import { Button, Dialog, EmptyState, Field, Input } from "../ui";

export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function CreateTenant({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { ep } = useApp();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => ep.createTenant(name.trim(), slugify(name)),
    onSuccess: async (t) => {
      await qc.invalidateQueries({ queryKey: keys.tenants });
      onClose();
      void navigate({ to: "/t/$tid", params: { tid: t.id } });
    },
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Create an organisation"
      description="You become its owner and can invite your team."
      onSubmit={() => name.trim() && create.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!name.trim()}>
            Create
          </Button>
        </>
      }
    >
      <Field label="Name" hint={name.trim() ? `Address name: ${slugify(name) || "—"}` : undefined} error={create.error ? errorText(create.error) : undefined}>
        {(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus placeholder="Acme Inc." maxLength={200} />}
      </Field>
    </Dialog>
  );
}

export function HomePage() {
  const tenants = useTenants();
  const [creating, setCreating] = useState(false);
  if (tenants.isPending) return <LoadingRows rows={2} />;
  if (tenants.data?.length) {
    const last = lastTenant();
    const target = tenants.data.find((t) => t.id === last) ?? tenants.data.find((t) => t.tenant_role !== "operator") ?? tenants.data[0]!;
    return <Navigate to="/t/$tid" params={{ tid: target.id }} replace />;
  }
  return (
    <>
      <PageHeader title="Welcome" />
      <QueryView query={tenants}>
        {() => (
          <EmptyState
            icon={<Building2 />}
            title="You are not in any organisation yet"
            action={
              <Button variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setCreating(true)}>
                Create an organisation
              </Button>
            }
          >
            If your company already uses Matura, ask an admin to invite you. Or create an organisation for your team.
          </EmptyState>
        )}
      </QueryView>
      <CreateTenant open={creating} onClose={() => setCreating(false)} />
    </>
  );
}
