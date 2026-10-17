import { useEffect, useRef, useState, type ReactNode } from "react";
import { cx } from "./cx";

/** A small disclosure menu: the trigger toggles it; Escape and clicks outside close it. */
export function Menu({ trigger, children, align = "start", side = "bottom", className }: { trigger: (props: { open: boolean; toggle: () => void }) => ReactNode; children: (close: () => void) => ReactNode; align?: "start" | "end"; side?: "top" | "bottom"; className?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return (
    <div ref={ref} className={cx("relative", className)}>
      {trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open ? (
        <div
          role="menu"
          className={cx(
            "fade-in absolute z-40 min-w-full rounded-md border border-border bg-bg-elevated p-1 shadow-lg shadow-black/5",
            align === "end" ? "right-0" : "left-0",
            side === "top" ? "bottom-full mb-1" : "top-full mt-1",
          )}
        >
          {children(() => setOpen(false))}
        </div>
      ) : null}
    </div>
  );
}

export function MenuItem({ children, onSelect, active, icon }: { children: ReactNode; onSelect: () => void; active?: boolean; icon?: ReactNode }) {
  return (
    <button
      role="menuitem"
      onClick={onSelect}
      className={cx("flex h-8 w-full items-center gap-2 rounded px-2 text-left text-[13px] hover:bg-bg-muted", active ? "text-fg font-medium" : "text-fg-muted hover:text-fg")}
    >
      {icon ? <span className="text-fg-subtle [&_svg]:size-4">{icon}</span> : null}
      <span className="min-w-0 flex-1 truncate">{children}</span>
    </button>
  );
}

export function MenuLabel({ children }: { children: ReactNode }) {
  return <div className="px-2 pt-1.5 pb-1 text-[11px] font-medium tracking-wide text-fg-subtle uppercase">{children}</div>;
}

export function MenuSeparator() {
  return <div className="my-1 h-px bg-border" />;
}
