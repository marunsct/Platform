import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import { ChevronDown } from "lucide-react";
import { cx } from "./cx";

const control =
  "h-8 w-full rounded-md border border-border bg-bg-elevated px-2.5 text-[13px] text-fg placeholder:text-fg-subtle " +
  "outline-none transition-shadow focus:border-accent focus:ring-3 focus:ring-ring disabled:opacity-60 " +
  "aria-invalid:border-danger";

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(control, className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div className={cx("relative", className)}>
      <select className={cx(control, "appearance-none pr-7")} {...rest}>
        {children}
      </select>
      <ChevronDown aria-hidden className="pointer-events-none absolute top-1/2 right-2 size-3.5 -translate-y-1/2 text-fg-subtle" />
    </div>
  );
}

/** A labelled form field; the child control gets the generated id. */
export function Field({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string; children: (id: string) => ReactNode }) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-xs font-medium text-fg">
        {label}
      </label>
      {children(id)}
      {error ? <p className="text-xs text-danger">{error}</p> : hint ? <p className="text-xs text-fg-muted">{hint}</p> : null}
    </div>
  );
}
