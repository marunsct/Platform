# Customer portal

The customer portal is where an organisation's owners and admins manage their people and access without calling the
API: members, invitations, app access and role grants, workspaces, each app's roles, and My account. maturad serves
it at **`/portal/`**; there is nothing else to deploy. Technical details: [spec §5.2](../spec/02-technical-specification.md).

## Using it

| Page | What you can do | Who |
|---|---|---|
| Overview | organisation name, plan, status; counts of members, pending invitations, apps and workspaces; rename | everyone sees it; owners and admins rename |
| Members | search; change a member's organisation role (owner, admin, member); remove a member; leave | everyone sees it; owners and admins change roles; only owners make or unmake owners; the last owner cannot be demoted or leave |
| Invitations | invite by email with an organisation role and a role per enabled app; resend; revoke; state badges (pending, accepted, revoked, expired) | owners and admins |
| App access | enable or disable apps; grant a member an app role for the whole organisation or one workspace; revoke | everyone sees it; owners and admins change it |
| Workspaces | list, create, rename | everyone sees them; owners and admins change them |
| Roles | each app's roles, the permissions they grant and which is the default | everyone; installation operators also create, edit and delete roles (they apply in every organisation) |
| Agents | create service accounts and AI agents (client secret shown once); rotate the secret; deactivate (kill switch) or reactivate; delete | owners and admins |
| Directory sync | SCIM base URL and tokens (created, shown once, revoked); map identity-provider groups to app roles | owners manage tokens; owners and admins manage mappings |
| Audit log | filter by actor and action; open an event for its details and hashes; verify the hash chain | owners and admins |
| My account | your profile as Matura knows it, a link to edit it at the identity provider, your organisations | everyone |

The organisation switcher at the top of the sidebar lists your organisations (operators see all of them) and keeps
you on the same page when you switch. Theme (light, dark, system) is in the user menu at the bottom.

When an invitation is sent the portal also shows its link once, so you can pass it on yourself if this server has
no SMTP relay (`MATURA_SMTP_ADDR`).

## Running it

Nothing extra: `go build ./cmd/maturad` embeds the built portal (`internal/portal/dist` is committed). Point a
browser at `http://localhost:8080/portal/`.

Sign-in uses the realm's public client `matura-console` with authorization code and PKCE. The client's redirect
URIs must include `<public origin>/portal/*` and its post-logout redirect URIs the same; the realm export in
`keycloak/realm` has `http://localhost:8080/portal/*`. Settings:

| Variable | Used for |
|---|---|
| `MATURA_ISSUER` | the issuer the portal signs in with, given to the browser in `/portal/config.json`; its origin is added to the CSP `connect-src` |
| `MATURA_PORTAL_CLIENT_ID` | the public client (default `matura-console`) |
| `MATURA_AUTH=dev` | development only: the portal asks which user id, email and name to act as (and whether as an operator) and sends `X-Matura-Dev-*` headers instead of signing in |

Tokens stay in memory. Reloading the page sends the browser through Keycloak again, which returns straight away
while its session lasts, so you rarely see a login form twice.

## Developing it

Source: `web/portal` (React 19, Vite, TypeScript, Tailwind CSS 4, TanStack Router and Query, Lucide icons). Node
22 or newer.

```sh
cd web/portal
npm ci
npm run dev        # http://localhost:5173/portal/, API proxied to maturad on :8080 (MATURAD_URL to change)
npm test           # vitest: PKCE, sign-in flow, API client
npm run typecheck
npm run build      # writes ../../internal/portal/dist; commit it with your change
```

`make portal` runs `npm ci && npm run build`; `make portal-test` runs the typecheck and tests. The Go test
`TestPortalServed` (in `internal/api`) checks maturad serves the index, assets, client routes and `config.json`
with the strict CSP; it reads the committed build, so rebuild before running it after a change.

The dev server's origin `http://localhost:5173` is already a redirect URI of `matura-console`, so the full OIDC
flow works there against a local Keycloak. With a maturad in dev mode no Keycloak is needed.

### Layout

| Path | What |
|---|---|
| `src/lib/` | `pkce.ts`, `auth.ts` (OIDC and dev sign-in), `api.ts` (fetch wrapper, problem+json errors, Idempotency-Key, If-Match), `endpoints.ts` (one function per API call), `types.ts` |
| `src/ui/` | the design system: Button, Input, Select, Field, Dialog and ConfirmDialog (native `<dialog>`), Table, Badge, Toast, EmptyState, Menu, Spinner and Skeleton |
| `src/app/` | shell (sidebar, organisation switcher, user menu), router, query hooks, loading/error/forbidden states, theme |
| `src/pages/` | one file per page |
| `src/styles.css` | design tokens as CSS variables for light and dark, mapped into the Tailwind theme |

### Rules

- **Tokens, not colours.** Components use the token utilities (`bg-bg-elevated`, `text-fg-muted`, `border-border`,
  `bg-accent` …); new colours go into `styles.css` for both themes.
- **The CSP is strict.** No inline `<script>` or `<style>`, no `eval`, no third-party hosts. React `style` props are
  fine (they go through CSSOM), but prefer classes. Fonts and images ship with the build.
- **Every view has four states:** loading (skeleton rows), error with retry, empty with a next step, and 403 as
  "you need admin access" (`QueryView` in `src/app/states.tsx` does the first two and the last).
- **Mutations** show a toast on success and the server's problem `detail` on failure. Role changes and grant
  revokes update the screen first and roll back on error.
- **Keep the bundle small:** the whole app is about 130 KB gzipped (budget 170 KB, doc 18). Check `npm run build`'s
  output before adding a dependency.

## Not built yet

From doc 05 and TS8/TS9: API keys and service accounts, groups, per-workspace member lists, member deactivation,
bulk CSV invitations and temporary passwords, tenant-scoped custom roles (RL-7; operators edit an app's roles today),
sessions, security policies, per-tenant SSO pages, audit sinks and export, agent grants and expiry, webhooks, branding, and translations. Doc 18's wider gates (Storybook, axe,
size-limit and Lighthouse in CI, DTCG tokens through Style Dictionary, Base UI, view transitions, command palette)
are still to come.
