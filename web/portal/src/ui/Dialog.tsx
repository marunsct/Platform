import { useEffect, useRef, type FormEvent, type ReactNode } from "react";
import { X } from "lucide-react";
import { Button } from "./Button";
import { cx } from "./cx";

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  /** When set, the body is a form and Enter submits it. */
  onSubmit?: () => void;
  className?: string;
}

/** A modal on the native <dialog> element: focus trap, Escape and the top layer come from the browser. */
export function Dialog({ open, onClose, title, description, children, footer, onSubmit, className }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  const body = (
    <>
      <div className="flex items-start justify-between gap-4 px-5 pt-4">
        <div>
          <h2 className="text-sm font-semibold text-fg">{title}</h2>
          {description ? <p className="mt-1 text-[13px] text-fg-muted">{description}</p> : null}
        </div>
        <Button variant="ghost" size="sm" aria-label="Close" onClick={onClose} className="-mr-2 px-1.5" icon={<X className="size-4" />} />
      </div>
      {children ? <div className="flex flex-col gap-4 px-5 py-4">{children}</div> : <div className="h-4" />}
      {footer ? <div className="flex justify-end gap-2 border-t border-border bg-bg-subtle px-5 py-3">{footer}</div> : null}
    </>
  );

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => e.target === ref.current && onClose()}
      className={cx(
        "fade-in m-auto w-[min(440px,calc(100vw-32px))] overflow-hidden rounded-[10px] border border-border bg-bg-elevated p-0 text-fg",
        className,
      )}
    >
      {open ? (
        onSubmit ? (
          <form
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              onSubmit();
            }}
          >
            {body}
          </form>
        ) : (
          body
        )
      ) : null}
    </dialog>
  );
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel,
  danger,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  loading?: boolean;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={loading} autoFocus>
            {confirmLabel}
          </Button>
        </>
      }
    />
  );
}
