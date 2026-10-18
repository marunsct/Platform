import { useState } from "react";
import { FlaskConical } from "lucide-react";
import type { DevAuth } from "../lib/auth";
import { Button, Field, Input } from "../ui";

const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Sign-in for maturad's development mode (MATURA_AUTH=dev): pick who to be. Never shown with OIDC. */
export function DevSignIn({ auth, onDone }: { auth: DevAuth; onDone: () => void }) {
  const [userId, setUserId] = useState<string>(() => crypto.randomUUID());
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [operator, setOperator] = useState(false);
  const valid = uuidRe.test(userId.trim());
  return (
    <div className="flex min-h-dvh items-center justify-center px-4">
      <form
        className="fade-in flex w-full max-w-sm flex-col gap-4 rounded-[10px] border border-border bg-bg-elevated p-6"
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          auth.signIn({ userId: userId.trim(), email: email.trim(), name: name.trim(), operator });
          onDone();
        }}
      >
        <div>
          <div className="mb-2 inline-flex items-center gap-1.5 rounded-full bg-warning-subtle px-2 py-0.5 text-[11px] font-medium text-warning">
            <FlaskConical className="size-3" /> development mode
          </div>
          <h1 className="text-base font-semibold">Sign in as a test user</h1>
          <p className="mt-1 text-[13px] text-fg-muted">This server trusts request headers (MATURA_AUTH=dev). Never use it outside development.</p>
        </div>
        <Field label="User id" error={valid ? undefined : "A UUID"}>{(id) => <Input id={id} value={userId} onChange={(e) => setUserId(e.target.value)} className="font-mono text-xs" />}</Field>
        <Field label="Email">{(id) => <Input id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="owner@example.com" />}</Field>
        <Field label="Name">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        <label className="flex items-center gap-2 text-[13px]">
          <input type="checkbox" checked={operator} onChange={(e) => setOperator(e.target.checked)} className="accent-[var(--accent)]" /> Installation operator
        </label>
        <Button type="submit" variant="primary" disabled={!valid}>
          Continue
        </Button>
      </form>
    </div>
  );
}
