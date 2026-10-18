import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { Shell } from "./Shell";
import { AccountPage } from "../pages/Account";
import { AgentsPage } from "../pages/Agents";
import { AppsPage } from "../pages/Apps";
import { AuditPage } from "../pages/Audit";
import { HomePage } from "../pages/Home";
import { InvitationsPage } from "../pages/Invitations";
import { MembersPage } from "../pages/Members";
import { NotFoundPage } from "../pages/NotFound";
import { OverviewPage } from "../pages/Overview";
import { RolesPage } from "../pages/Roles";
import { ScimPage } from "../pages/Scim";
import { WorkspacesPage } from "../pages/Workspaces";

const root = createRootRoute({ component: () => <Shell />, notFoundComponent: NotFoundPage });
const home = createRoute({ getParentRoute: () => root, path: "/", component: HomePage });
const account = createRoute({ getParentRoute: () => root, path: "/account", component: AccountPage });
const tenant = createRoute({ getParentRoute: () => root, path: "/t/$tid", component: Outlet });
const overview = createRoute({ getParentRoute: () => tenant, path: "/", component: OverviewPage });
const members = createRoute({ getParentRoute: () => tenant, path: "/members", component: MembersPage });
const invitations = createRoute({
  getParentRoute: () => tenant,
  path: "/invitations",
  component: InvitationsPage,
  validateSearch: (s: Record<string, unknown>): { invite?: boolean } => (s.invite === true || s.invite === "true" ? { invite: true } : {}),
});
const apps = createRoute({ getParentRoute: () => tenant, path: "/apps", component: AppsPage });
const workspaces = createRoute({ getParentRoute: () => tenant, path: "/workspaces", component: WorkspacesPage });
const roles = createRoute({ getParentRoute: () => tenant, path: "/roles", component: RolesPage });
const agents = createRoute({ getParentRoute: () => tenant, path: "/agents", component: AgentsPage });
const audit = createRoute({ getParentRoute: () => tenant, path: "/audit", component: AuditPage });
const scim = createRoute({ getParentRoute: () => tenant, path: "/scim", component: ScimPage });

const routeTree = root.addChildren([home, account, tenant.addChildren([overview, members, invitations, apps, workspaces, roles, agents, audit, scim])]);

export const BASE_PATH = "/portal";

export function makeRouter() {
  return createRouter({ routeTree, basepath: BASE_PATH, defaultPreload: "intent", scrollRestoration: true });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof makeRouter>;
  }
}
