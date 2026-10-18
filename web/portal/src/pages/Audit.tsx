import { useState } from "react";
import { useInfiniteQuery, useMutation } from "@tanstack/react-query";
import { BadgeCheck, ScrollText, Search } from "lucide-react";
import { useApp } from "../app/context";
import { keys, useCurrentTenant } from "../app/queries";
import { ErrorState, LoadingRows, NeedAdmin, PageHeader, errorText } from "../app/states";
import { ApiError } from "../lib/api";
import type { AuditEvent } from "../lib/types";
import { Badge, Button, EmptyState, Input, Table, Td, Th, THead, Tr, useToast } from "../ui";

function actorLabel(e: AuditEvent): string {
  const a = e.actor;
  return a.email || a.id?.slice(0, 8) || a.kind;
}

export function AuditPage() {
  const { ep } = useApp();
  const { tid, canManage } = useCurrentTenant();
  const toast = useToast();
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const log = useInfiniteQuery({
    queryKey: keys.audit(tid, actor, action),
    enabled: canManage,
    initialPageParam: "",
    queryFn: ({ pageParam }) => ep.audit(tid, { actor, action, cursor: pageParam }),
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const verify = useMutation({
    mutationFn: () => ep.verifyAudit(tid),
    onSuccess: (v) =>
      v.ok ? toast.success("Audit chain verified", `${v.events} events checked, no tampering found.`) : toast.error("Audit chain is broken", `First break at event ${v.first_break?.seq}: ${v.first_break?.reason}`),
    onError: (e) => toast.error("Couldn't verify", errorText(e)),
  });

  if (!canManage) return <><PageHeader title="Audit log" /><NeedAdmin what="read the audit log" /></>;
  const events = log.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every change to members, roles, agents and security settings, in a tamper-evident chain."
        actions={
          <Button icon={<BadgeCheck className="size-3.5" />} loading={verify.isPending} onClick={() => verify.mutate()}>
            Verify chain
          </Button>
        }
      />
      <div className="mb-3 flex flex-wrap gap-2">
        <div className="relative max-w-xs">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input aria-label="Filter by action" placeholder="Action prefix, e.g. membership." value={action} onChange={(e) => setAction(e.target.value)} className="pl-8" />
        </div>
        <Input aria-label="Filter by actor" placeholder="Actor email" value={actor} onChange={(e) => setActor(e.target.value)} className="max-w-xs" />
      </div>
      {log.isPending ? (
        <LoadingRows />
      ) : log.isError ? (
        log.error instanceof ApiError && log.error.forbidden ? <NeedAdmin what="read the audit log" /> : <ErrorState error={log.error} onRetry={() => void log.refetch()} />
      ) : events.length === 0 ? (
        <EmptyState icon={<ScrollText />} title="No events match" />
      ) : (
        <>
          <Table>
            <THead>
              <tr>
                <Th>When</Th>
                <Th>Actor</Th>
                <Th>Action</Th>
                <Th className="hidden md:table-cell">Target</Th>
              </tr>
            </THead>
            <tbody>
              {events.map((e) => (
                <Tr key={e.id} onClick={() => setOpen(open === e.id ? null : e.id)} className="cursor-pointer">
                  <Td className="whitespace-nowrap text-fg-muted">{new Date(e.time).toLocaleString()}</Td>
                  <Td>
                    <div className="flex items-center gap-1.5">
                      {actorLabel(e)}
                      {e.actor.kind !== "user" ? <Badge>{e.actor.kind}</Badge> : null}
                    </div>
                  </Td>
                  <Td>
                    <code className="text-xs">{e.action}</code>
                    {open === e.id ? (
                      <pre className="mt-2 max-w-xl overflow-x-auto rounded-md bg-bg-muted p-2 text-[11px] whitespace-pre-wrap">
                        {JSON.stringify({ target: e.target, ip: e.ip, request_id: e.request_id, seq: e.seq, hash: e.hash, data: e.data }, null, 2)}
                      </pre>
                    ) : null}
                  </Td>
                  <Td className="hidden max-w-[16rem] truncate text-fg-muted md:table-cell">{e.target}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
          {log.hasNextPage ? (
            <div className="mt-3 flex justify-center">
              <Button loading={log.isFetchingNextPage} onClick={() => void log.fetchNextPage()}>
                Load older events
              </Button>
            </div>
          ) : null}
        </>
      )}
    </>
  );
}
