import { Link } from "@tanstack/react-router";
import { Building2, ExternalLink } from "lucide-react";
import { useApp } from "../app/context";
import { useMe, useTenants } from "../app/queries";
import { Avatar, Card, PageHeader, QueryView } from "../app/states";
import { Badge, EmptyState, Table, Td, Th, THead, Tr } from "../ui";

export function AccountPage() {
  const { config } = useApp();
  const me = useMe();
  const tenants = useTenants();
  return (
    <>
      <PageHeader title="My account" description="Your profile as Matura knows it, and the organisations you belong to." />
      <QueryView query={me} rows={2}>
        {({ user, operator }) => {
          const name = user.display_name || user.email || "You";
          return (
            <Card>
              <div className="flex items-center gap-3 border-b border-border p-4">
                <Avatar name={name} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 font-medium text-fg">
                    {name} {operator ? <Badge tone="accent">operator</Badge> : null}
                  </div>
                  <div className="text-xs text-fg-muted">{user.email ?? "no email"}</div>
                </div>
                {config.auth === "oidc" && config.issuer ? (
                  <a href={config.issuer.replace(/\/$/, "") + "/account"} className="inline-flex items-center gap-1 text-[13px] text-accent hover:underline">
                    Edit profile and security <ExternalLink className="size-3.5" aria-hidden />
                  </a>
                ) : null}
              </div>
              <dl className="divide-y divide-border">
                {(
                  [
                    ["Email", <span className="flex items-center gap-2">{user.email ?? "—"} {user.email ? <Badge tone={user.email_verified ? "success" : "warning"}>{user.email_verified ? "verified" : "not verified"}</Badge> : null}</span>],
                    ["Display name", user.display_name ?? "—"],
                    ["Language", user.locale ?? "browser default"],
                    ["Status", <Badge tone={user.status === "active" ? "success" : "warning"}>{user.status}</Badge>],
                    ["User id", <span className="font-mono text-xs select-all">{user.id}</span>],
                  ] as const
                ).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between gap-4 px-4 py-3">
                    <dt className="text-fg-muted">{k}</dt>
                    <dd className="text-right text-fg">{v}</dd>
                  </div>
                ))}
              </dl>
            </Card>
          );
        }}
      </QueryView>
      <h2 className="mt-8 mb-3 text-sm font-semibold text-fg">My organisations</h2>
      <QueryView query={tenants} rows={2}>
        {(list) => {
          const mine = list.filter((t) => t.tenant_role !== "operator");
          return mine.length === 0 ? (
            <EmptyState icon={<Building2 />} title="You are not in any organisation yet">
              Ask an admin to invite you, or open an invitation link from your email.
            </EmptyState>
          ) : (
            <Table>
              <THead>
                <tr>
                  <Th>Organisation</Th>
                  <Th>Your role</Th>
                  <Th className="w-24" aria-label="Open" />
                </tr>
              </THead>
              <tbody>
                {mine.map((t) => (
                  <Tr key={t.id}>
                    <Td>
                      <div className="font-medium text-fg">{t.name}</div>
                      <div className="font-mono text-xs text-fg-muted">{t.slug}</div>
                    </Td>
                    <Td>
                      <Badge tone={t.tenant_role === "member" ? "neutral" : "accent"}>{t.tenant_role}</Badge>
                    </Td>
                    <Td className="text-right">
                      <Link to="/t/$tid" params={{ tid: t.id }} className="text-[13px] text-accent hover:underline">
                        Open
                      </Link>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          );
        }}
      </QueryView>
    </>
  );
}
