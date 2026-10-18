import type { ReactNode } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { CircleAlert, Lock } from "lucide-react";
import { ApiError } from "../lib/api";
import { Button, EmptyState, Skeleton } from "../ui";

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-tight text-fg">{title}</h1>
        {description ? <p className="mt-1 text-[13px] text-fg-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function LoadingRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-3 rounded-md border border-border bg-bg-elevated p-4" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="size-7 rounded-full" />
          <Skeleton className="h-3.5 w-1/3" />
          <Skeleton className="ml-auto h-3.5 w-20" />
        </div>
      ))}
    </div>
  );
}

export function NeedAdmin({ what }: { what: string }) {
  return (
    <EmptyState icon={<Lock />} title="You need admin access">
      Only owners and admins of this organisation can {what}. Ask one of them to change your role if you need it.
    </EmptyState>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <EmptyState
      icon={<CircleAlert />}
      title={error instanceof ApiError && error.notFound ? "Not found" : "Couldn't load this"}
      action={onRetry ? <Button onClick={onRetry}>Try again</Button> : undefined}
    >
      {error instanceof ApiError && error.notFound ? "It may have been removed, or you are not a member of this organisation." : msg}
    </EmptyState>
  );
}

/** Renders loading, error (403 as "you need admin") and success states of one query. */
export function QueryView<T>({ query, children, forbidden = "see this", rows }: { query: UseQueryResult<T>; children: (data: T) => ReactNode; forbidden?: string; rows?: number }) {
  if (query.isPending) return <LoadingRows rows={rows} />;
  if (query.isError) {
    if (query.error instanceof ApiError && query.error.forbidden) return <NeedAdmin what={forbidden} />;
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  return <>{children(query.data)}</>;
}

export function errorText(err: unknown): string {
  if (err instanceof ApiError && err.forbidden) return "You need admin access for this.";
  return err instanceof Error ? err.message : String(err);
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function relative(iso: string): string {
  const diff = new Date(iso).getTime() - Date.now();
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 3_600_000) return rtf.format(Math.round(diff / 60_000), "minute");
  if (abs < 86_400_000) return rtf.format(Math.round(diff / 3_600_000), "hour");
  return rtf.format(Math.round(diff / 86_400_000), "day");
}

export function Avatar({ name }: { name: string }) {
  const initials = name
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");
  return (
    <span aria-hidden className="inline-flex size-7 shrink-0 items-center justify-center rounded-full bg-bg-muted text-[11px] font-medium text-fg-muted">
      {initials || "?"}
    </span>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={"rounded-md border border-border bg-bg-elevated " + (className ?? "")}>{children}</div>;
}
