import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cx } from "./cx";
import { Spinner } from "./Spinner";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-hover border-transparent",
  secondary: "bg-bg-elevated text-fg border-border hover:bg-bg-muted",
  ghost: "bg-transparent text-fg-muted border-transparent hover:bg-bg-muted hover:text-fg",
  danger: "bg-danger text-white border-transparent hover:bg-danger-hover",
};

const sizes: Record<Size, string> = {
  sm: "h-7 px-2.5 text-xs gap-1.5",
  md: "h-8 px-3 text-[13px] gap-2",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ReactNode;
}

export function Button({ variant = "secondary", size = "md", loading, icon, className, children, disabled, type = "button", ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cx(
        "inline-flex shrink-0 items-center justify-center rounded-md border font-medium whitespace-nowrap",
        "transition-colors duration-100 disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        sizes[size],
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner className="size-3.5" /> : icon}
      {children}
    </button>
  );
}
