import { cx } from "./cx";

export function Spinner({ className, label }: { className?: string; label?: string }) {
  return (
    <svg className={cx("animate-spin", className ?? "size-4")} viewBox="0 0 16 16" fill="none" role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : true}>
      <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2" />
      <path d="M14.5 8A6.5 6.5 0 0 0 8 1.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded-md bg-bg-muted", className ?? "h-4 w-full")} />;
}
