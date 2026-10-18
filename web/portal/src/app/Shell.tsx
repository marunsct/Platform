import { useEffect, useState, type ReactNode } from "react";
import { Link, Outlet, useMatches, useNavigate } from "@tanstack/react-router";
import {
  AppWindow,
  Building2,
  Check,
  ChevronsUpDown,
  Bot,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  Mail,
  Menu as MenuIcon,
  Monitor,
  Moon,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Sun,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { useApp } from "./context";
import { useCurrentTenant, useMe, useTenants } from "./queries";
import { Avatar } from "./states";
import { applyTheme, lastTenant, readTheme, rememberTenant, type ThemeChoice } from "./theme";
import { Badge, Menu, MenuItem, MenuLabel, MenuSeparator, Skeleton, cx } from "../ui";

const tenantNav = [
  { to: "/t/$tid", label: "Overview", icon: LayoutDashboard, exact: true },
  { to: "/t/$tid/members", label: "Members", icon: Users },
  { to: "/t/$tid/invitations", label: "Invitations", icon: Mail },
  { to: "/t/$tid/apps", label: "App access", icon: AppWindow },
  { to: "/t/$tid/workspaces", label: "Workspaces", icon: FolderKanban },
  { to: "/t/$tid/roles", label: "Roles", icon: ShieldCheck },
  { to: "/t/$tid/agents", label: "Agents", icon: Bot },
  { to: "/t/$tid/scim", label: "Directory sync", icon: RefreshCw },
  { to: "/t/$tid/audit", label: "Audit log", icon: ScrollText },
] as const;

function NavLink({ to, params, icon: Icon, label, exact, onNavigate }: { to: string; params?: Record<string, string>; icon: typeof Users; label: string; exact?: boolean; onNavigate?: () => void }) {
  return (
    <Link
      to={to}
      params={params as never}
      onClick={onNavigate}
      activeOptions={{ exact: !!exact }}
      className="flex h-8 items-center gap-2.5 rounded-md px-2 text-[13px] text-fg-muted transition-colors hover:bg-bg-muted hover:text-fg"
      activeProps={{ className: "bg-bg-muted !text-fg font-medium", "aria-current": "page" }}
    >
      <Icon className="size-4 shrink-0" aria-hidden />
      {label}
    </Link>
  );
}

/** The tenant the sidebar is about: the one in the address, else the last one visited (on pages like My account). */
function useNavTenant() {
  const tenants = useTenants();
  const { tid } = useCurrentTenant();
  const id = tid || lastTenant() || "";
  const entry = tenants.data?.find((t) => t.id === id) ?? (tid ? undefined : tenants.data?.[0]);
  return { tid: entry?.id ?? tid, entry };
}

function TenantSwitcher() {
  const tenants = useTenants();
  const { tid, entry } = useNavTenant();
  const navigate = useNavigate();
  const matches = useMatches();
  const routeId = matches.at(-1)?.routeId ?? "/t/$tid/";
  const section = routeId.startsWith("/t/$tid") ? routeId : "/t/$tid/";

  if (tenants.isPending) return <Skeleton className="h-9 w-full" />;
  const list = tenants.data ?? [];
  return (
    <Menu
      className="w-full"
      trigger={({ open, toggle }) => (
        <button
          onClick={toggle}
          aria-expanded={open}
          aria-haspopup="menu"
          className="flex h-9 w-full items-center gap-2 rounded-md border border-border bg-bg-elevated px-2 text-left hover:bg-bg-muted"
        >
          <span className="inline-flex size-5 shrink-0 items-center justify-center rounded bg-accent text-[10px] font-semibold text-accent-fg">
            {(entry?.name ?? "?").slice(0, 1).toUpperCase()}
          </span>
          <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{entry?.name ?? (tid ? "Organisation" : "Choose organisation")}</span>
          <ChevronsUpDown className="size-3.5 shrink-0 text-fg-subtle" aria-hidden />
        </button>
      )}
    >
      {(close) => (
        <>
          <MenuLabel>Organisations</MenuLabel>
          <div className="max-h-72 overflow-y-auto">
            {list.length === 0 ? <p className="px-2 py-1.5 text-xs text-fg-muted">You are not a member of any organisation yet.</p> : null}
            {list.map((t) => (
              <MenuItem
                key={t.id}
                active={t.id === tid}
                icon={t.id === tid ? <Check /> : <Building2 />}
                onSelect={() => {
                  close();
                  rememberTenant(t.id);
                  void navigate({ to: section as "/t/$tid", params: { tid: t.id } });
                }}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="truncate">{t.name}</span>
                  <span className="text-[11px] text-fg-subtle">{t.tenant_role}</span>
                </span>
              </MenuItem>
            ))}
          </div>
        </>
      )}
    </Menu>
  );
}

function UserMenu() {
  const { auth } = useApp();
  const me = useMe();
  const [theme, setTheme] = useState<ThemeChoice>(readTheme);
  const id = auth.identity();
  const name = me.data?.user.display_name || id?.name || me.data?.user.email || id?.email || "Signed in";
  const email = me.data?.user.email || id?.email;
  const pick = (t: ThemeChoice) => {
    setTheme(t);
    applyTheme(t);
  };
  return (
    <Menu
      side="top"
      className="w-full"
      trigger={({ open, toggle }) => (
        <button onClick={toggle} aria-expanded={open} aria-haspopup="menu" className="flex w-full items-center gap-2 rounded-md p-1.5 text-left hover:bg-bg-muted">
          <Avatar name={name} />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px] font-medium text-fg">{name}</span>
            {email && email !== name ? <span className="block truncate text-[11px] text-fg-muted">{email}</span> : null}
          </span>
          {me.data?.operator ? <Badge tone="accent">operator</Badge> : null}
        </button>
      )}
    >
      {(close) => (
        <>
          <Link to="/account" onClick={close} className="flex h-8 items-center gap-2 rounded px-2 text-[13px] text-fg-muted hover:bg-bg-muted hover:text-fg">
            <UserRound className="size-4 text-fg-subtle" /> My account
          </Link>
          <MenuSeparator />
          <MenuLabel>Theme</MenuLabel>
          <MenuItem icon={<Sun />} active={theme === "light"} onSelect={() => pick("light")}>Light</MenuItem>
          <MenuItem icon={<Moon />} active={theme === "dark"} onSelect={() => pick("dark")}>Dark</MenuItem>
          <MenuItem icon={<Monitor />} active={theme === "system"} onSelect={() => pick("system")}>System</MenuItem>
          <MenuSeparator />
          <MenuItem icon={<LogOut />} onSelect={() => auth.signOut()}>Sign out</MenuItem>
        </>
      )}
    </Menu>
  );
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { config } = useApp();
  const { tid } = useNavTenant();
  return (
    <nav aria-label="Main" className="flex h-full flex-col gap-4 p-3">
      <div className="flex h-7 items-center gap-2 px-1">
        <span className="inline-flex size-5 items-center justify-center rounded-[5px] bg-fg text-[11px] font-bold text-bg">M</span>
        <span className="text-[13px] font-semibold tracking-tight">{config.product ?? "Matura"}</span>
      </div>
      <TenantSwitcher />
      {tid ? (
        <div className="flex flex-col gap-0.5">
          {tenantNav.map((n) => (
            <NavLink key={n.to} to={n.to} params={{ tid }} icon={n.icon} label={n.label} exact={"exact" in n && n.exact} onNavigate={onNavigate} />
          ))}
        </div>
      ) : null}
      <div className="flex flex-col gap-0.5">
        <div className="px-2 pb-1 text-[11px] font-medium tracking-wide text-fg-subtle uppercase">You</div>
        <NavLink to="/account" icon={UserRound} label="My account" onNavigate={onNavigate} />
      </div>
      <div className="mt-auto">
        <UserMenu />
      </div>
    </nav>
  );
}

export function Shell({ children }: { children?: ReactNode }) {
  const [open, setOpen] = useState(false);
  const { tid } = useCurrentTenant();
  useEffect(() => {
    if (tid) rememberTenant(tid);
  }, [tid]);
  return (
    <div className="flex min-h-dvh">
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 border-r border-border bg-bg-subtle md:block">
        <Sidebar />
      </aside>
      {open ? (
        <div className="fixed inset-0 z-30 md:hidden">
          <div className="absolute inset-0 bg-[var(--overlay)]" onClick={() => setOpen(false)} />
          <aside className="fade-in absolute inset-y-0 left-0 w-64 border-r border-border bg-bg-subtle">
            <Sidebar onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-12 items-center gap-2 border-b border-border bg-bg px-4 md:hidden">
          <button aria-label={open ? "Close menu" : "Open menu"} onClick={() => setOpen(!open)} className="rounded p-1 text-fg-muted hover:bg-bg-muted">
            {open ? <X className="size-5" /> : <MenuIcon className="size-5" />}
          </button>
          <span className="text-[13px] font-semibold">Matura</span>
        </header>
        <main className={cx("mx-auto w-full max-w-5xl flex-1 px-4 py-8 md:px-8")}>{children ?? <Outlet />}</main>
      </div>
    </div>
  );
}
