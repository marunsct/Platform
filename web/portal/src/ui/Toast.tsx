import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { CircleAlert, CircleCheck, X } from "lucide-react";
import { cx } from "./cx";

type ToastTone = "success" | "error" | "info";
interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  detail?: string;
}

interface ToastApi {
  success(title: string, detail?: string): void;
  error(title: string, detail?: string): void;
  info(title: string, detail?: string): void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const t = useContext(ToastContext);
  if (!t) throw new Error("useToast outside ToastProvider");
  return t;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(1);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const push = useCallback(
    (tone: ToastTone, title: string, detail?: string) => {
      const id = next.current++;
      setItems((xs) => [...xs.slice(-3), { id, tone, title, detail }]);
      setTimeout(() => dismiss(id), tone === "error" ? 8000 : 4000);
    },
    [dismiss],
  );
  const api = useMemo<ToastApi>(
    () => ({
      success: (t, d) => push("success", t, d),
      error: (t, d) => push("error", t, d),
      info: (t, d) => push("info", t, d),
    }),
    [push],
  );
  return (
    <ToastContext.Provider value={api}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(360px,calc(100vw-32px))] flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            role={t.tone === "error" ? "alert" : "status"}
            className="fade-in pointer-events-auto flex items-start gap-2.5 rounded-md border border-border bg-bg-elevated px-3 py-2.5 shadow-lg shadow-black/5"
          >
            {t.tone === "error" ? (
              <CircleAlert className="mt-0.5 size-4 shrink-0 text-danger" />
            ) : (
              <CircleCheck className={cx("mt-0.5 size-4 shrink-0", t.tone === "success" ? "text-success" : "text-accent")} />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-medium text-fg">{t.title}</p>
              {t.detail ? <p className="mt-0.5 text-xs break-words text-fg-muted">{t.detail}</p> : null}
            </div>
            <button aria-label="Dismiss" onClick={() => dismiss(t.id)} className="rounded p-0.5 text-fg-subtle hover:text-fg">
              <X className="size-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
