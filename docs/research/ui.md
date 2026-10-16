# UI Research & Design Doc — Enterprise-Readiness Layer (Apache-2.0, self-hosted)

Status: research draft, 2026-10-11. Scope: every UI surface. (a) hosted auth pages (Keycloak themes), (b) tenant admin
portal, (c) operator console, (d) embeddable React components + web components, (e) public trust page.
Hard constraints: OSI-licensed dependencies only, white-label per app and per tenant, WCAG 2.2 AA, i18n incl. RTL,
dark mode, best-in-class frontend performance.

Package versions and licences below come from the npm registry (queried 2026-10-11) unless a different source is cited.
Where the claims come from secondary sources and could not be checked against a primary one, they are marked **(unverified)**.

| Package | Latest | Date | Licence |
|---|---|---|---|
| react | 19.3.0 | 2026-09-09 | MIT |
| vite | 8.3.4 | 2026-10-08 | MIT |
| @tanstack/react-router | 1.170.42 | 2026-10-10 | MIT |
| @tanstack/react-start | 1.168.61 | 2026-10-10 | MIT |
| @tanstack/react-query | 5.104.1 | 2026-10-02 | MIT |
| @tanstack/react-table | 9.2.8 (v9.0.0 on 2026-08-04) | 2026-10-08 | MIT |
| @tanstack/react-virtual | 3.14.14 | 2026-10-09 | MIT |
| @tanstack/db | 0.13.0 (pre-1.0) | 2026-10-10 | MIT |
| next | 16.4.0 | 2026-10-06 | MIT |
| babel-plugin-react-compiler | 1.0.0 | 2025-10-07 | MIT |
| @base-ui/react | 1.9.0 | 2026-10-09 | MIT |
| radix-ui (unified pkg) | 1.7.0 | 2026-10-05 | MIT |
| @radix-ui/themes | 3.3.0 | 2026-01-31 | MIT |
| react-aria-components | 1.22.1 | 2026-10-09 | Apache-2.0 |
| @ark-ui/react | 5.39.3 | 2026-10-05 | MIT |
| tailwindcss | 4.3.3 | 2026-07-16 | MIT |
| style-dictionary | 5.6.1 | 2026-10-10 | Apache-2.0 |
| motion | 14.1.0 | 2026-10-09 | MIT |
| cmdk | 1.1.1 | 2025-03-14 (stale) | MIT |
| @lingui/core | 6.9.1 | 2026-10-09 | MIT |
| react-intl (FormatJS) | 12.1.4 | 2026-10-05 | BSD-3-Clause |
| i18next | 26.4.3 | 2026-10-10 | MIT |
| uplot | 1.6.32 | 2025-03-14 | MIT |
| echarts | 6.1.0 | 2026-05-19 | Apache-2.0 |
| recharts | 3.10.1 | 2026-07-25 | MIT |
| @visx/visx | 4.0.0 | 2026-06-11 | MIT |
| lit | 3.3.3 | 2026-05-14 | BSD-3-Clause |
| @r2wc/react-to-web-component | 2.1.1 | 2026-02-24 | MIT |
| keycloakify | 11.16.1 | 2026-10-02 | MIT |
| @storybook/react-vite | 10.6.1 | 2026-09-29 | MIT |
| @lhci/cli | 0.15.1 | 2025-06-25 | Apache-2.0 |
| @argos-ci/cli | 6.9.6 | 2026-10-04 | MIT |
| @fontsource-variable/inter | 5.3.0 | 2026-07-19 | OFL-1.1 |
| geist (font) | 1.7.2 | 2026-06-01 | OFL-1.1 |

---

## 1. Framework for the consoles

### Options
| Option | Fit for an authenticated, self-hosted console | Notes |
|---|---|---|
| **React 19.3 + Vite 8 SPA + TanStack Router/Query** | Excellent | Static assets only (served by the Go/Java API, nginx or a CDN). No Node server to run, patch or harden. Same language as the embeddables. |
| Next.js 16 (App Router, RSC) | Mediocre | RSC/SSR help with SEO and first paint on public pages. Our consoles sit behind login and gain little from that, and every self-hosted deployment would then need a Node runtime. RSC's Flight protocol had a CVSS 10 unauthenticated RCE, CVE-2025-55182 "React2Shell" (Dec 2025), which hit default Next 15/16 App Router apps. More server surface is a real liability for a security product. |
| TanStack Start (1.168.x) | Good, as an upgrade path | Built on TanStack Router, client-first with optional SSR and server functions. The official v1 post is still titled "Release Candidate" (2025-09-23) and says "when 1.0 ships we'll update this post". Third parties disagree on whether it is stable **(unverified)**. Starting on plain Router means we can adopt Start later without rewriting routes. |
| SvelteKit / Solid | Strong performance, wrong ecosystem | Smaller runtimes, but the embeddable SDK has to be React-first (that is what customers use, as Clerk and WorkOS show). Two component stacks would double the design-system work. |

### Recommendation
**React 19.3 + Vite 8 SPA, TanStack Router (file-based, typed search params) + TanStack Query, React Compiler 1.0 enabled.**
- No SSR for (b) or (c). The shell is a static `index.html` plus hashed immutable chunks, and the API serves it under a strict CSP (`script-src 'self'`, no inline scripts).
- (e) Trust page is prerendered to static HTML at build time and refreshed by the operator console's "publish". It ships near-zero JS. Options are Vite SSG with React `renderToStaticMarkup`, or TanStack Start's static prerender once 1.0 is confirmed.
- Router features we use: `defaultPreload: 'intent'` (prefetches loader and chunk on hover/touchstart), route-level code splitting, loaders that call `queryClient.ensureQueryData`, typed and validated search params for table filters (URL-as-state, so table views are shareable), and `defaultViewTransition` with direction-aware `types`.
- React Compiler 1.0 has been stable since 2025-10-07. On Vite 8, `@vitejs/plugin-react` v6 dropped internal Babel for oxc, so the compiler goes in through `@rolldown/plugin-babel` + `babel-plugin-react-compiler` **(unverified, 3rd-party guide)**. It removes most manual `useMemo`/`useCallback` and cuts re-render cost in dense tables.
- React 19.3 (2026-09-09) makes `<ViewTransition>` and Fragment refs stable, per a search snippet of react.dev's 19.3 post. The page itself could not be fetched, so confirm before relying on it. `<Activity>` shipped in 19.2 and keeps state in hidden tabs and drawers (for example, the audit-log filter panel).

Sources: https://react.dev/blog/2025/10/07/react-compiler-1 · https://react.dev/blog/2026/09/09/react-19-3 ·
https://react.dev/blog/2025/04/23/react-labs-view-transitions-activity-and-more ·
https://tanstack.com/blog/announcing-tanstack-start-v1 (source: github.com/TanStack/tanstack.com/blob/main/src/blog/announcing-tanstack-start-v1.md) ·
https://tanstack.com/router/latest/docs/framework/react/examples/view-transitions · https://tanstack.com/router/latest/docs/api/router/RouterOptionsType ·
https://recca0120.github.io/en/2026/04/14/react-compiler-vite-v6/ · https://www.vulncheck.com/blog/cve-2025-55182-react-nextjs ·
https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182 · https://makerkit.dev/blog/tutorials/tanstack-start-vs-nextjs

---

## 2. Component system, tokens, colour

### Primitive libraries (all OSI)
| Library | Licence | Strengths | Weaknesses |
|---|---|---|---|
| **Base UI** (`@base-ui/react` 1.9) | MIT | From the Radix/MUI/Floating UI authors. v1 stable since Dec 2025 with ~35 accessible components, new minors monthly. Unstyled, uses a `render` prop instead of `asChild`. Has Combobox, Autocomplete, NumberField, Menubar and Toast. | Younger than Radix. |
| Radix Primitives (`radix-ui` 1.7) | MIT | Most battle-tested, ~130M downloads/mo. WorkOS Widgets and Radix Themes build on it. | Development slowed after WorkOS acquired Modulz (2022) **(secondary sources)**. |
| React Aria Components 1.22 | Apache-2.0 | The strongest a11y and i18n: 30+ locale calendars, RTL, date/time/number fields, drag-and-drop, virtualized collections. | More verbose and a heavier styling story. |
| Ark UI 5.x / Park UI | MIT | Zag.js state machines, works in React/Vue/Solid/Svelte. | Smaller community. Park UI is Panda-CSS-centric. |

**shadcn/ui** (MIT, copy-in source, Tailwind v4) supports Base UI as an alternative to Radix through `--base` (Jan 2026). Secondary sources report that Base UI became the default for new projects on 2026-07-03 and that Radix is still supported **(unverified)**. Either way, shadcn gives us owned source, consistent APIs and a registry we can publish our own components to (`registry:base`).

**Recommendation:** shadcn/ui pattern (owned source in `packages/ui`) **on Base UI** for all primitives. Use **React Aria Components only for date/time/range pickers and calendars** (audit-log time filters, key expiry), where its locale and RTL handling is unmatched. Do not mix Radix in. Our tokens, not shadcn's defaults, are the source of styling.

### Tailwind CSS v4.3
- CSS-first config (`@theme`), native cascade layers, `@property`, `color-mix()` and OKLCH defaults. v4.2 added full **logical-property utilities** (`ps-*`, `me-*`, `pbs-*`, inset/inline sizes), which RTL depends on. v4.3 added scrollbar utilities, `@container-size`, compound `@variant` and default values for functional utilities.
- **Shadow DOM caveat:** `@property` rules do not apply inside shadow roots, and Tailwind v4 relies on them (e.g. `--tw-shadow`, `--tw-ring`). For web components, hoist the `@property` block into `document.head` once and keep everything else in the shadow root. Prefix our vars (`--matura-*` / `--tw-` renamed at build) so we don't collide with a host page running Tailwind v3/v4 (see §6).

### Design tokens (white-label)
- Source of truth: **W3C DTCG Format 2025.10**, the first stable spec (Final CG Report, 2025-10-28). It supports themes and multi-brand, OKLCH/Display-P3 colour, aliases and component-level references.
- Build: **Style Dictionary v5** (Apache-2.0, native DTCG) emits:
  1. CSS custom properties (`:root`, `[data-theme=dark]`, `[data-density=compact]`) consumed by Tailwind `@theme inline`;
  2. TS token types for the `appearance` API;
  3. Keycloakify login CSS;
  4. email template variables;
  5. a JSON schema for the tenant-branding editor.
- Three tiers: **reference** (oklch ramps, type scale) → **semantic** (`bg.subtle`, `fg.muted`, `border.default`, `accent.solid`, `danger.fg`) → **component** (`button.primary.bg`). Tenants override **semantic** tokens only. That is a small, safe surface: brand hue, neutral tint, radius, font family, logo, density.
- Runtime per-tenant theme: the API serves `GET /t/{tenant}/theme.css` (ETag, `Cache-Control: public, max-age=300, stale-while-revalidate`). It is generated from a brand seed colour → 12-step OKLCH ramp → contrast-validated (WCAG 2.x ratio enforced, APCA reported). The file is ~1–2 KB, loaded with `<link>` before app CSS, so there is no flash and no JS needed.

### Colour: OKLCH
- Perceptually uniform lightness means equal L gives equal perceived brightness across hues. That is the problem Stripe solved with a custom perceptual tool ("Designing accessible color systems"), and Linear's 2024 redesign moved theme generation from HSL to LCH so a few inputs (base, accent, contrast) yield a whole theme **(LCH detail via summaries)**.
- Ramp semantics follow the Radix Colors 12-step convention (1–2 app backgrounds, 3–5 component backgrounds/hover/active, 6–8 borders, 9–10 solid fills, 11–12 text). This is well understood by shadcn/Radix users and works for both light and dark.
- Generation: fix L per step (light: 0.99 → 0.21; dark: 0.15 → 0.95), scale chroma by a gamut-safe curve (clamp to sRGB with a P3 enhancement under `@media (color-gamut: p3)`), and keep hue from the seed. Unit tests assert 4.5:1 for step 11 on step 1/2 and 3:1 for step 8 borders against bg (for non-text UI, SC 1.4.11).

### How the reference products get their look
- **Clerk:** `appearance` prop with `theme` (prebuilt base themes, incl. a `shadcn` theme that reads Tailwind v4 vars), `variables` (colorPrimary, fonts, radius), `elements` (per-DOM-node classes/styles) and per-component overrides. Nested components (e.g. UserProfile opened from UserButton) take their own appearance. Our model copies this (§6).
- **WorkOS Widgets:** React components (UsersManagement, UserProfile, UserSecurity, UserSessions, OrganizationSwitcher) built on **Radix Themes** + TanStack Query as peer deps. Theming is a `theme` prop with Radix Themes options (accentColor, grayColor, radius, scaling, appearance). Auth uses a short-lived widget token plus allowed web origins (CORS). This validates our architecture.
- **Vercel Geist:** Geist Sans/Mono (OFL). Near-black #171717 on white, gray scale with high-contrast steps, tight-tracked semibold display type, 1px borders instead of shadows, very restrained colour (blue accent only for focus and links). Third-party token catalogs conflict on exact values **(unverified)**.
- **Linear:** LCH theme generator, low-chroma neutrals tinted by the accent, dense 13px UI, heavy keyboard focus (command palette, single-key shortcuts), sub-200ms motion, reduced chrome (the 2024 redesign cut visual noise in the sidebar, tabs and headers).
- **Stripe:** perceptual colour system, generous whitespace, strong typographic hierarchy, very polished micro-interactions in Dashboard. Stripe Apps' UI toolkit enforces tokens so third parties stay on-brand.

Sources: https://base-ui.com · https://infoq.com/news/2026/02/baseui-v1-accessible/ · https://mui.com/blog/2026-and-beyond/ ·
https://ui.shadcn.com/docs/changelog · https://blog.openreplay.com/shadcn-ui-radix-base-ui-switch/ ·
https://www.pkgpulse.com/guides/shadcn-ui-vs-base-ui-vs-radix-components-2026 · https://react-spectrum.adobe.com/react-aria/ ·
https://ark-ui.com · https://tailwindcss.com/blog/tailwindcss-v4-3 · https://laravel-news.com/tailwindcss-4-2-0 ·
https://www.w3.org/community/design-tokens/2025/10/28/design-tokens-specification-reaches-first-stable-version/ ·
https://www.designtokens.org/tr/2025.10/ · https://styledictionary.com · https://stripe.com/blog/accessible-color-systems ·
https://linear.app/now/how-we-redesigned-the-linear-ui · https://linear.app/changelog/2024-03-20-new-linear-ui ·
https://clerk.com/docs/react/guides/customizing-clerk/appearance-prop/overview ·
https://clerk.com/docs/react/guides/customizing-clerk/appearance-prop/themes · https://workos.com/docs/widgets ·
https://workos.com/blog/new-widgets-released-user-profile-and-organization-switcher · https://vercel.com/geist ·
https://github.com/vercel/geist-font · https://www.radix-ui.com/colors/docs/palette-composition/understanding-the-scale

---

## 3. Motion and fluidity

**Principle: CSS and platform first, JS motion only where physics or layout requires it.**

- **View Transitions API**
  - Same-document transitions became Baseline Newly Available in Oct 2025 (Firefox 144). Use them for route changes (TanStack Router `defaultViewTransition`, with direction types for back/forward), list↔detail morphs (`view-transition-name` on avatar/title), and theme toggles (circular reveal).
  - React 19.3 `<ViewTransition>` integrates with transitions and Suspense.
  - Cross-document transitions (`@view-transition { navigation: auto; }`) work in Chromium and Safari and are an **Interop 2026** focus area. Firefox status is unconfirmed. Use them on the Keycloak login flow (multi-page FTL: username → password → OTP) as progressive enhancement. Browsers without support get a plain navigation.
- **Motion** (formerly Framer Motion, `motion` 14.1, **MIT**). Motion+ is a paid membership for premium APIs/examples. Its FAQ says premium components are "currently" MIT but "an additional license may be required for site-builder or code-generation companies". **Use only the MIT core**, never Motion+, so the dependency tree stays fully OSI. Load it lazily via `LazyMotion` + `m` (~5 KB initial) only in the consoles for layout animations (reordering role lists), drag gestures, and spring-driven sheets/drawers. Embeddables do not depend on Motion; they use CSS only.
- **Springs in CSS:** `linear()` easing approximates spring curves without JS. Generate 2–3 tokens (`--ease-spring-snappy`, `--ease-spring-gentle`) and use them for popovers and dialogs. Pair with `@starting-style` + `transition-behavior: allow-discrete` for enter/exit of `[popover]`, `<dialog>` and `display:none` toggles.
- **Scroll-driven animations** (`animation-timeline: scroll()/view()`): Chromium since 115 and Safari 26. Firefox stable is still behind a pref as of 152 (Jun 2026) and it is an Interop 2026 target. Use them only for decoration (sticky-header shadow on scroll, trust-page reveal), wrapped in `@supports (animation-timeline: view())`, with the end state as default.
- **Optimistic UI:** TanStack Query `onMutate`/`useMutation` variables for role changes, invite revoke and toggles. React 19 `useOptimistic` + form Actions in forms. Roll back with a toast + Undo. Destructive actions get a 5-second undo toast instead of a confirm dialog where it is reversible server-side (soft delete). Irreversible actions (delete tenant, rotate signing keys) use a typed-confirmation dialog.
- **Skeletons:** only for regions taking >300 ms. Skeletons match final layout boxes exactly (CLS 0). Use a delay-to-show (~150 ms) to avoid flicker, plus Suspense boundaries per panel, not per page. Avoid shimmer under reduced motion (static fill instead).
- **prefers-reduced-motion:** global token `--motion-scale: 0` under `@media (prefers-reduced-motion: reduce)`. View transitions fall back to cross-fade ≤100 ms or none. Motion's `useReducedMotion` / `MotionConfig reducedMotion="user"`. A per-user override lives in user settings.
- **Frame budgets:** 60 Hz = 16.7 ms/frame, 120 Hz = 8.3 ms. Animate only `transform`/`opacity`/`filter`/`clip-path`. No layout-thrashing reads in animation loops. Long tasks over 50 ms are a CI failure in interaction tests. Use `content-visibility: auto` on off-screen panels and `contain: layout paint` on table rows.
- **Durations:** micro 100–150 ms (hover, press), small 150–200 ms (popover, tooltip), medium 200–300 ms (dialog, drawer, route). Never more than 400 ms on functional UI. Enter: ease-out/spring. Exit: ~70% of the enter duration.

Sources: https://web.dev/blog/same-document-view-transitions-are-now-baseline-newly-available ·
https://developer.chrome.com/blog/view-transitions-in-2025 · https://ecorpit.com/interop-2026-web-platform-developer-guide/ ·
https://motion.dev/plus · https://cdn.jsdelivr.net/npm/motion@13.1.0/README.md ·
https://www.buildmvpfast.com/blog/css-scroll-driven-animations-replace-js-2026 ·
https://developer.mozilla.org/docs/Web/CSS/easing-function/linear · https://developer.mozilla.org/docs/Web/CSS/@starting-style ·
https://blog.logrocket.com/react-viewtransition-vs-motion

---

## 4. Data-heavy views

- **Tables: TanStack Table v9 (MIT, v9.0 Aug 2026) + TanStack Virtual 3.**
  - v9 is fully tree-shakeable per feature and per built-in function. A minimal table got ~0.6 KB smaller in 9.2.8, and devtools show the per-feature size.
  - The headless design fits our tokens.
  - Server-side sorting, filtering and pagination for members/tenants (cursor-based). Client-side only under 2k rows.
  - Row virtualization when there are more than ~100 rows: fixed row heights per density (36 px compact / 44 px comfortable) for O(1) measuring, and sticky header via CSS `position: sticky`.
  - Column resizing, pinning, visibility, and saved views persisted in URL search params plus user prefs.
  - a11y: real `<table>` semantics, `aria-rowcount`/`aria-rowindex` on virtualized rows, a roving-tabindex grid pattern only where cells are interactive.
- **Audit log viewer (infinite scroll + live tail)**
  - `useInfiniteQuery` with an opaque cursor (`(occurred_at, id)` keyset) from the API. Page size 100, virtualized, `fetchNextPage` when within 10 rows of the end.
  - Live tail over **SSE** `GET /audit/stream?since=<cursor>` with `Last-Event-ID` resume. New events prepend into a buffer. If the user is scrolled to the top, rows animate in (opacity/translate, 150 ms). Otherwise a "↑ 12 new events" pill appears, and the scroll position is kept stable (anchor by row id).
  - Pause/resume tail, an event detail side sheet (JSON diff view, actor, IP, geo, user agent), filters (actor, action, target, time range via React Aria DateRangePicker), and CSV/JSON export as a server-side async job with download link.
  - Rendering: monospace for ids, relative time with absolute time in a tooltip (`Intl.RelativeTimeFormat` / `Intl.DateTimeFormat`), and severity colour chips that never rely on colour alone (icon + text).
- **Charts**
  | Lib | Licence | Use |
  |---|---|---|
  | **uPlot** | MIT | Time series (auth volume, error rates, latency). ~50 KB min, canvas, fastest line renderer (9 ms for 100k points; ~2.5k full updates/s at 50k points in ApexCharts' 2026 benchmark, a vendor benchmark). No animations or stacking, which is fine for ops data. |
  | **visx** 4 | MIT | Bespoke SVG pieces: readiness-score radial gauge, control-status heat grid, sparklines. Tree-shakeable low-level primitives that are themeable via tokens. |
  | Recharts 3 | MIT | Acceptable for the simple tenant billing usage chart, but SVG gets slow on large series. Optional. |
  | ECharts 6 | Apache-2.0 | Lazy-load only if we need complex charts (Sankey, geo). ~300 KB+, so never in the initial bundle. |
  **Pick uPlot + visx.** Wrap both in a `<Chart>` that reads tokens (categorical palette from OKLCH ramps, validated for CVD), supports dark mode by reading CSS vars at draw time, and renders an accessible data table / `aria-describedby` summary.

Sources: https://tanstack.com/table/latest · https://github.com/TanStack/table/releases · https://tanstack.com/virtual/latest ·
https://tanstack.com/query/latest/docs/framework/react/guides/infinite-queries · https://github.com/leeoniya/uPlot ·
https://apexcharts.com/blog/javascript-chart-library-benchmark/ · https://airbnb.io/visx · https://echarts.apache.org ·
https://html.spec.whatwg.org/multipage/server-sent-events.html

---

## 5. Command palette, keyboard-first, real-time, local-first

- **Command palette (⌘K / Ctrl K):**
  - `cmdk` (MIT) is the de-facto standard (used by Linear-likes and shadcn's `Command`), but its last release was **2025-03**. Alternative: build the palette on **Base UI Autocomplete/Combobox + Dialog** in our own `packages/ui`, which keeps one primitive library and avoids an unmaintained dependency. Recommendation: shadcn-style `Command` API implemented on Base UI, with fuzzy matching from a tiny lib (e.g. `match-sorter`, MIT) or our own scorer.
  - Sources: static nav, recent items, entity search (tenants, members, API keys via a debounced server search), and actions ("Invite member", "Rotate key", "Toggle dark mode"), all role-gated.
- **Keyboard-first:**
  - Global shortcut registry (`g m` → Members, `g a` → Audit, `/` focus search, `?` cheat-sheet overlay, `j/k` row navigation, `x` select, `Esc` closes topmost layer).
  - Use `tinykeys` (MIT, ~650 B) or a custom hook.
  - Never steal keys inside inputs. Every shortcut is discoverable in tooltips and menus (`<kbd>`). Shortcuts are configurable and can be disabled (WCAG 2.1.4 Character Key Shortcuts).
- **Real-time:**
  - **SSE** for server→client: audit tail, tenant health, job progress (exports, SCIM syncs, backup-restore tests), and "someone else changed this" invalidations. SSE is plain HTTP, works through corporate proxies and HTTP/2 multiplexing, and auto-reconnects with `Last-Event-ID`. A single multiplexed `/events` stream per tab is shared across tabs via `BroadcastChannel` + leader election.
  - Event payloads are mostly **query-key invalidations** (`{type:"invalidate", keys:[["members",tenantId]]}`), which keeps the cache logic in TanStack Query.
  - WebSockets are not needed. Revisit only for collaborative editing.
- **Local-first:** **TanStack DB** (0.13, still pre-1.0/alpha-beta) adds collections, differential-dataflow live queries (sub-ms incremental updates) and optimistic transactions on top of Query. It pairs with ElectricSQL (Apache-2.0) to sync Postgres shapes over HTTP. **Defer.** Admin data is authoritative-server and permissioned, so the complexity isn't worth it before TanStack DB 1.0. Design query keys and mutation functions so we can move collections to TanStack DB later (e.g. the operator's all-tenants grid with instant client filtering).

Sources: https://github.com/pacocoursey/cmdk · https://ui.shadcn.com/docs/components/command · https://github.com/jamiebuilds/tinykeys ·
https://github.com/TanStack/db · https://blog.openreplay.com/tanstack-db-reactive-uis/ · https://electric-sql.com/docs ·
https://www.w3.org/WAI/WCAG22/Understanding/character-key-shortcuts

---

## 6. Embeddable components

**Packages**
- `@matura/react`: ESM-only, `"sideEffects": ["*.css"]`, peer deps `react >=18.3 <20`. Per-component entry points (`@matura/react/members-table`). Exports `<MaturaProvider>`, `UserButton`, `OrgSwitcher`, `MembersTable`, `AuditLog`, `SSOSetup` (wizard), `ApiKeys`, `SecuritySettings`, plus headless hooks (`useOrganization`, `useMembers`, `useSession`) for teams that want their own UI.
- `@matura/react` CSS ships in `@layer matura.base, matura.components, matura.overrides` with prefixed classes (`matura-*`) and prefixed vars (`--matura-*`). Host CSS outside layers always wins. This is the "bring your own CSS" escape hatch.
- `@matura/elements`: custom elements for non-React hosts (`<matura-user-button>`, `<matura-members-table>`, …).
  - **Approach:** wrap the **same React components** as custom elements. Use `@r2wc/react-to-web-component` (MIT) or a 100-line in-house wrapper with attribute/property mapping, events as `CustomEvent`, and an open Shadow DOM. One implementation means feature parity.
  - The React runtime is bundled in this build. Measure it, and consider a **Preact + preact/compat** build of the elements bundle to cut ~40 KB gz. Base UI and TanStack generally work under compat, but this needs a CI test.
  - **Lit (BSD-3)** stays an option for one ultra-light element (`<matura-user-button>`, under 10 KB) if size demands, but avoid a second implementation of complex widgets.
- **Shadow DOM style isolation:**
  - The component CSS is a constructable stylesheet (`adoptedStyleSheets`), shared across instances.
  - Tailwind v4 `@property` rules are hoisted to `document` once, renamed to `--matura-tw-*` at build (PostCSS plugin) to avoid host collisions.
  - Inherited properties (font, color) are reset at `:host { all: initial }`, then re-applied from tokens.
  - Portals (menus, dialogs, tooltips): Base UI `Portal container` must target a node **inside the shadow root**. Otherwise styles are lost and focus management breaks. Use the top layer (`popover`, `<dialog>`) where possible.
  - Expose `::part()` for key nodes (`part="root header row action-primary"`) and CSS custom properties for theming. Slots for custom empty states and row actions.
- **Theming API (`appearance`, modelled on Clerk + Radix Themes):**
  ```ts
  appearance = {
    baseTheme: "default" | "neutral" | "shadcn" | Theme,   // shadcn reads host --primary/--radius etc.
    variables: { colorPrimary, colorNeutral, colorDanger, fontFamily, fontSize, radius, density: "compact"|"comfortable", colorScheme: "light"|"dark"|"system" },
    elements: { membersTable__row: "my-class" | CSSProperties, ... },   // stable, documented element keys
    layout: { logoPlacement, socialButtonsVariant, showOptionalFields },
    locale: "ar" | ..., localization: Partial<Messages>
  }
  ```
  `variables` compile at runtime into the same semantic tokens as §2 (OKLCH ramp from `colorPrimary`), set as `--matura-*` on the provider root or `:host`. Per-component props override the provider, and nested components take their own `appearance` (Clerk semantics). For web components the same object is passed as a JS property (`el.appearance = {...}`) or a JSON attribute.
- **Auth & data:** a short-lived embed token is minted by the host's backend (our SDK) and scoped to tenant + user + allowed origins (CORS allow-list per app, like WorkOS widgets). TanStack Query is bundled internally (not a peer) with an isolated `QueryClient` to avoid version conflicts. Hosts already on Query can pass theirs.
- **Budgets:** `@matura/react` core (provider + UserButton + OrgSwitcher) ≤ 25 KB gz excluding React. MembersTable ≤ 30 KB gz. Elements full bundle ≤ 90 KB gz (React) / ≤ 55 KB gz (Preact build). Enforced with `size-limit`.

Sources: https://clerk.com/docs/react/guides/customizing-clerk/appearance-prop/overview · https://workos.com/docs/widgets ·
https://viget.com/articles/embeddable-widgets-with-vite-react-tailwind-4-web-components ·
https://github.com/tailwindlabs/tailwindcss/pull/15975 · https://benfrain.com/?p=4756 · https://github.com/bitovi/react-to-web-component ·
https://lit.dev · https://developer.mozilla.org/docs/Web/CSS/::part · https://base-ui.com/react/utils/portal (Portal container)

---

## 7. Keycloak login UI

- **Keycloakify v11** is current (11.16.1, 2026-10-02, MIT; dist-tag `keycloakify_v10` for legacy). The README says it is compatible with Keycloak **11 → 26**, and that themes built before KC 26 must be rebuilt with the latest Keycloakify. Login and email themes are written in React with Vite, and every page renders in **Storybook**. Pages can be ejected individually. Because pages are plain React components, we can drop PatternFly entirely and use our own `packages/ui` + tokens. (docs.keycloakify.dev was unreachable from the research sandbox, so feature details come from search snippets and the README.)
- **Keycloak 26.x:** latest line 26.7 (2026-07-09) adds **SCIM API (preview)**, Admin API v2 (experimental), SSF security-event transmitter and step-up for SAML. The default login theme is `keycloak.v2` (PatternFly 5) and v1 is deprecated.
- **Account console:** Keycloakify offers *Single-Page* (Account v3, the KC 25+ default: React/PatternFly, customizable mostly via PF variables, no Storybook, heavy) or *Multi-Page* (Keycloakify-maintained fork of v1, CSS-level customization, Storybook, lacks advanced features, call the Account REST API yourself).
  **Recommendation:** don't invest in the KC account console. Our **tenant/user portal** owns "My account" (profile, password, passkeys, MFA devices, sessions, linked IdPs) via Keycloak's Account REST API / Admin API through our backend. Ship a minimal Multi-Page account theme that redirects to the portal, so there is one design language.
- **Passkeys:** KC 26.4 (2025-09-30) made passkeys GA with **conditional UI** (autofill) and modal UI integrated into the default login forms. Enable it in *WebAuthn Passwordless Policy*. A "Conditional - credential" authenticator skips 2FA when a passkey was the primary factor, and passkeys appear in re-authentication.
  UX rules for our theme:
  - The username field has `autocomplete="username webauthn"` and calls conditional mediation on page load (`navigator.credentials.get({mediation:"conditional"})`).
  - A visible "Sign in with a passkey" button for modal flow.
  - After a password login, prompt "Create a passkey?". Chrome's *automatic passkey upgrade* needs conditional **create**, which KC had not adopted as of 26.4.x per the community forum **(unverified, re-check 26.7)**.
  - Clear device/sync-provider naming in the portal's passkey list.
- **Fast login pages (LCP < 1 s on fast 4G-class / < 1.5 s slow 4G):**
  - The login bundle is separate from the consoles: JS ≤ 60 KB gz (React + login pages, code-split per page via `React.lazy` by `pageId`), CSS ≤ 15 KB gz with critical CSS inlined in the FTL head.
  - Tenant theme CSS (§2) via `<link rel=preload>`. One preloaded variable font subset (Latin, ≤ 35 KB woff2) with metric-matched fallback (`size-adjust`), so FOUT causes no CLS.
  - Logo served as SVG or sized AVIF with explicit width/height. LCP element = heading text, not an image.
  - Keycloak: `cacheThemes=true`, `cacheTemplates=true`. Hashed assets served with `Cache-Control: immutable` from the reverse proxy with Brotli and HTTP/2/3.
  - No third-party scripts. CSP nonce-free (`script-src 'self'`).
  - Speculation: `<link rel=prefetch>` the next step's chunk (password page) when the username is typed.
  - RUM: `web-vitals` beacons to our collector.
  - Optional: cross-document view transitions between steps (§3).

Sources: https://github.com/keycloakify/keycloakify · https://docs.keycloakify.dev/theme-types/account-theme ·
https://docs.keycloakify.dev/theme-types/account-theme/multi-page · https://docs.keycloakify.dev/documentation/v11/configuration-options/keycloakversiontargets ·
https://www.keycloak.org/2025/09/passkeys-support-26-4 · https://www.keycloak.org/2025/09/keycloak-2640-released ·
https://www.keycloak.org/2026/07/keycloak-2670-released · https://www.keycloak.org/docs/latest/release_notes/index ·
https://forum.keycloak.org/t/chrome-doesnt-propose-to-create-passkey/31146 · https://web.dev/articles/passkey-form-autofill ·
https://www.stackhero.io/en-US/services/Keycloak/documentations/Customize-the-appearance/Understanding-Keycloak-theme-structure

---

## 8. Performance budgets

**Core Web Vitals (p75, field/RUM; "good" thresholds are LCP ≤ 2.5 s, INP ≤ 200 ms, CLS ≤ 0.1):**
| Surface | LCP | INP | CLS | Initial JS (gz) | CSS (gz) |
|---|---|---|---|---|---|
| Login pages | ≤ 1.0 s | ≤ 100 ms | ≤ 0.02 | ≤ 60 KB | ≤ 15 KB |
| Trust page | ≤ 1.0 s | ≤ 100 ms | ≤ 0.02 | ≤ 15 KB | ≤ 15 KB |
| Tenant portal / operator console (cold) | ≤ 1.8 s | ≤ 150 ms | ≤ 0.05 | ≤ 150 KB shell | ≤ 30 KB |
| Console route change (warm) | visual < 100 ms (preload on intent) | | | ≤ 50 KB/route chunk | |
| Embeddables | n/a (host) | ≤ 100 ms | 0 (reserve box) | see §6 | |

- **Code splitting:** per route (TanStack Router auto code-splitting) and per heavy widget (charts, JSON diff viewer, date pickers, SSO wizard IdP metadata parser). Vendor chunks stay stable for long-term caching. Rolldown-powered Vite 8 builds are fast enough to run budgets on every PR.
- **INP:**
  - Keep handlers under 50 ms, and use `startTransition` for filter/search re-renders.
  - The React Compiler removes needless re-renders, and virtualized tables keep DOM under ~1.5k nodes.
  - Yield in long work (`scheduler.yield()` where available, `await` chunking otherwise). Debounce server search to 150 ms.
- **CLS:** reserve space for async content (skeletons with exact size), `font-size-adjust`/`size-adjust` fallbacks, explicit media dimensions, and toasts in the top layer.
- **Fonts:**
  - **Inter Variable** (OFL-1.1) as default UI face. Broad script coverage (Latin, Cyrillic, Greek, Vietnamese), tabular numerals (`font-feature-settings: "tnum"`), and optical sizing in v4.
  - **Geist / Geist Mono** (OFL-1.1, Vercel + basement.studio) are good alternatives with narrower coverage. Geist Mono is used for ids and keys.
  - RTL scripts: **IBM Plex Sans Arabic** or **Noto Sans Arabic/Hebrew** (OFL), loaded only for `dir=rtl` locales via `unicode-range`.
  - Self-host woff2 subsets with `font-display: swap` + metric-matched fallback (generated by `fontaine`/capsize). Preload only the primary Latin subset. Tenants can swap the font family (allow-listed OFL fonts or uploaded woff2).
- **Images:** icons are **Lucide** (ISC) as tree-shaken inline SVG components. Tenant logos are stored as SVG (sanitised server-side with DOMPurify-equivalent) or rasterised to AVIF/WebP at 1x/2x with explicit dimensions. Illustrations are inline SVG using `currentColor` and tokens (theme-aware, tiny).
- **Tooling:**
  - **Lighthouse CI** (`@lhci/cli`, Apache-2.0) on login, trust and a console route against budgets (`budget.json`), with a self-hostable LHCI server.
  - **size-limit** (MIT) per package.
  - `rollup-plugin-visualizer` for bundle reports.
  - **web-vitals** (Apache-2.0) RUM → OpenTelemetry → the operator console's own health dashboard ("dogfood the readiness score").
  - Playwright traces for INP regressions on scripted interactions (open a 10k-row table, filter, open a sheet).

Sources: https://web.dev/articles/vitals · https://web.dev/articles/inp · https://github.com/GoogleChrome/lighthouse-ci ·
https://github.com/ai/size-limit · https://github.com/GoogleChrome/web-vitals · https://rsms.me/inter/ · https://github.com/rsms/inter (OFL) ·
https://github.com/vercel/geist-font · https://www.npmjs.com/package/geist · https://github.com/unjs/fontaine · https://lucide.dev/license

---

## 9. Accessibility, i18n, RTL

- **WCAG 2.2 AA** (and EN 301 549 / European Accessibility Act, in force since June 2025, relevant to EU enterprise buyers). The 2.2 criteria that matter most for us:
  - 2.4.11 Focus Not Obscured: sticky headers and toasts must not cover focus.
  - 2.4.13 Focus Appearance is AAA but adopt it anyway: 2px focus ring at ≥3:1.
  - 2.5.7 Dragging Movements: every drag-reorder has button alternatives.
  - 2.5.8 Target Size: ≥24×24 CSS px, even in compact density.
  - 3.2.6 Consistent Help: the help link sits in the same place on every page.
  - 3.3.7 Redundant Entry, in the SSO/SCIM wizard.
  - **3.3.8 Accessible Authentication:** no cognitive tests. Allow paste and password managers, support passkeys, and never block paste in OTP fields. Use `autocomplete="one-time-code"`.
- Practices:
  - Base UI / React Aria handle ARIA patterns, focus traps and return focus.
  - Every route sets `document.title` and moves focus to the `h1` (TanStack Router `onResolved`), with an `aria-live` route announcer.
  - Skip link, landmarks, and visible labels (no placeholder-only inputs).
  - Error summary on forms with links to fields.
  - Status uses colour + icon + text.
  - Charts get table fallbacks.
  - Respect `prefers-contrast: more` (boost border step 6→8, text 11→12) and `forced-colors: active` (system colours, visible focus).
- Testing: `@axe-core/playwright` (MPL-2.0, test-time only, not shipped) on every Storybook story and key flows, the Storybook a11y addon, manual screen-reader passes per release (NVDA+Firefox, VoiceOver+Safari, TalkBack), and keyboard-only e2e scripts. Publish a VPAT/ACR on the trust page.
- **i18n library: Lingui 6 (MIT).**
  - ICU MessageFormat, compile-time message compilation (no runtime parser), and a tiny runtime.
  - Macros (`<Trans>`, `t`) extract to PO/JSON catalogs, and per-locale catalogs are lazy-loaded per route.
  - It works for the consoles, embeddables (catalog overridable via `appearance.localization`) and the Keycloakify login theme (which also has to feed Keycloak `.properties` for server-rendered emails/errors; generate those from the same source catalog in CI).
  - FormatJS/react-intl (BSD-3) is the equivalent ICU option with a heavier runtime unless precompiled. i18next (MIT) is most popular but uses a non-ICU custom format by default, which makes translator-tool interop harder.
  - Use native `Intl.*` for dates, numbers, lists, plurals and relative time. Never use moment/date-fns locale bundles.
- **RTL:**
  - `<html dir lang>` is set from the locale, and the embeddables set `dir` on their root/`:host`.
  - **Logical properties only** (Tailwind v4.2 `ps-/pe-/ms-/me-/start-/end-/pbs-`), with a stylelint rule banning physical `left/right/ml/mr`.
  - Directional icons (chevrons, arrows, "back") flip via `rtl:-scale-x-100`. Don't flip logos, checkmarks or media controls.
  - Base UI `DirectionProvider` and React Aria `I18nProvider` for keyboard semantics (arrow keys reverse in RTL).
  - Bidi isolation (`<bdi>`, `unicode-bidi: isolate`) for user-generated names and emails inside RTL strings.
  - Visual regression runs in `ar` and `he` plus a pseudo-locale (accented, +35% length) to catch truncation.

Sources: https://www.w3.org/TR/WCAG22/ · https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/ ·
https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum · https://lingui.dev ·
https://formatjs.github.io · https://www.i18next.com · https://tolgee.io/blog/react-i18n-libraries-comparison ·
https://www.pkgpulse.com/guides/next-intl-vs-react-i18next-vs-lingui-react-i18n-2026 · https://intlayer.org/doc/benchmark/nextjs ·
https://react-spectrum.adobe.com/react-aria/internationalization.html · https://github.com/dequelabs/axe-core-npm

---

## 10. Visual design direction ("Quiet Precision")

Feel: Linear's density and keyboard focus, Vercel's restraint and monochrome confidence, Stripe's typographic polish and
perceptual colour. Calm surfaces with strong hierarchy and one accent colour that the tenant brand replaces.

- **Typography:** Inter Variable (UI) + Geist Mono (code, ids, keys, audit payloads).
  - Scale (px): 11 · 12 · **13 (console body)** · 14 · 16 (login/trust body) · 18 · 20 · 24 · 30 · 36 · 48 (trust hero).
  - Line height 1.45 body, 1.2 headings.
  - Weights 400/500/600 only. Headings get −1% to −2% tracking at ≥20px.
  - `tnum` in tables, metrics and timestamps. Sentence case everywhere. Max 72ch for prose.
- **Spacing:** 4px base. Tokens 0, 2, 4, 6, 8, 12, 16, 20, 24, 32, 40, 48, 64, 80. Page gutters 24 (console) and 16 (mobile). Card padding 16/20.
- **Density modes:** `comfortable` (default for tenant portal: controls 36px, rows 44px) and `compact` (default for operator console: controls 32px, rows 36px; targets stay ≥24px). Implemented as a `--density` multiplier on spacing/size tokens, user-selectable.
- **Radius:** a tenant-adjustable `--radius` (default 8px). Derived: controls = radius−2 (6), cards = radius (8), dialogs/sheets = radius+4 (12), pills = 9999. Allow 0–16 in branding.
- **Colour system:** OKLCH 12-step ramps (§2).
  - Neutral = brand hue at very low chroma (0.005–0.015), giving Linear-style tinted grays.
  - Accent = brand. Semantic ramps for success (green 150°), warning (amber 75°), danger (red 25°) and info (blue 250°). Compliance status uses these plus icons (✓ passing, ! at risk, × failing, ○ not evaluated).
  - Light bg = neutral-1 with surfaces at neutral-1/2. Dark bg = near-black neutral-1 (L≈0.15, never pure #000), with surfaces lifting by +0.02–0.03 L per elevation level.
  - Borders do most of the separation (1px neutral-6). Shadows are reserved for floating layers (popover/dialog), which in dark mode add a 1px top inner highlight.
  - Focus ring: 2px accent-8 with 2px offset, plus a high-contrast variant.
- **Layout:** left sidebar (collapsible to icons, 240px→56px), top bar with OrgSwitcher, ⌘K search and UserButton. Content max-width 1200 for forms and full-bleed for tables. The settings pattern is a two-column grid (label/description left, control right), as Vercel and Stripe do.
- **Components with character:**
  - Readiness score: radial gauge + per-pillar bars (SSO, SCIM, audit, RBAC, data lifecycle, security policies), each linking to a fix-it action.
  - SSO/SCIM setup wizard: stepper with IdP logos, copy-to-clipboard fields, a live "test connection" pane with streaming logs (SSE), and docs side panel per IdP.
  - Evidence/controls: status chips + timeline.
- **Empty states:**
  - Three parts: a small monochrome line illustration (inline SVG, `currentColor`, tokens), a one-sentence explanation, and a primary action + secondary "Learn more".
  - First-run states double as onboarding checklists.
  - Never a blank table: show the column headers plus the empty-state row.
- **Illustrations & icons:** Lucide (ISC) icons at a 1.5px stroke, 16/20px. A commissioned set of ~12 spot illustrations in the same stroke language, released CC-BY-4.0 or Apache-2.0 with the repo.
- **Motion personality:** quick and physical, never decorative in the consoles (§3). The trust page can be more expressive (scroll reveals) but still respects reduced motion.
- **Trust page:** static, fast, brandable. Sections: security overview, subprocessors, compliance badges/status (live from the operator console's control status), uptime, documents (with NDA gate), VPAT, contact. Print stylesheet.

**Storybook + visual regression**
- **Storybook 10** (MIT, `@storybook/react-vite`) for `packages/ui`, embeddables and every Keycloakify login page (Keycloakify ships Storybook support).
  - Toolbar globals: theme (light/dark/hc), density, locale (en, de, ar, he, ja, pseudo), tenant brand presets.
  - Interaction tests via the Storybook test runner / Vitest addon. a11y addon on.
- **Visual regression, all open-source paths:**
  - Default is **Playwright `toHaveScreenshot`** over the Storybook stories (iterate stories.json) in a pinned Docker image for deterministic fonts and rendering. Baselines live in git (LFS), and diffs are uploaded as CI artifacts.
  - Matrix: themes × {en, ar} × {comfortable, compact} for core components, with a smaller set for pages.
  - Review UI options: **Argos** (MIT CLI + open-source app, hosted free tier ~5k screenshots/mo) for a PR review workflow, or fully self-hosted **reg-suit** (MIT) / **BackstopJS** (MIT).
  - **Lost Pixel was archived** (team joined Figma), so do not adopt it. Chromatic is proprietary SaaS and is not used.

Sources: https://linear.app/now/how-we-redesigned-the-linear-ui · https://vercel.com/geist/introduction · https://stripe.com/blog/accessible-color-systems ·
https://www.radix-ui.com/colors · https://lucide.dev · https://storybook.js.org/docs · https://playwright.dev/docs/test-snapshots ·
https://argos-ci.com/blog/storybook-visual-testing-without-chromatic · https://argos-ci.com/blog/lost-pixel-alternatives ·
https://github.com/reg-viz/reg-suit · https://github.com/garris/BackstopJS · https://storybook.keycloakify.dev

---

## UI decisions

1. **React 19.3 + Vite 8 SPA, TanStack Router + Query, React Compiler on, for the tenant portal and operator console.** Fully static assets mean no Node runtime to self-host or patch (avoiding the RSC server surface; cf. React2Shell CVE-2025-55182). The consoles are behind auth, so SSR adds little. TanStack Start stays an upgrade path on the same router.
2. **The trust page is prerendered static HTML** (~0 JS, LCP ≤ 1 s), regenerated on publish from the operator console.
3. **shadcn/ui-style owned components on Base UI (MIT).** One modern, actively shipped, unstyled primitive layer that shadcn now supports first-class. Copy-in source gives full design control. **React Aria Components only for date/time pickers and calendars**, for its locale and RTL quality.
4. **Tailwind CSS v4.3 + DTCG 2025.10 tokens → Style Dictionary v5** as the single token pipeline feeding consoles, embeddables, Keycloak login CSS and emails. Vendor-neutral, stable spec, OKLCH-native.
5. **OKLCH 12-step ramps generated from a tenant seed colour, with contrast enforced in code.** White-label that stays accessible: tenants pick a brand colour and cannot ship an inaccessible theme. Served as cached per-tenant `theme.css` (no FOUC, no JS).
6. **Three-tier tokens; tenants override only the semantic tier** (brand hue, neutral tint, radius, font, density, logo). This keeps the customisation surface small and supportable.
7. **Motion is CSS-first** (View Transitions, `@starting-style`, `linear()` springs). Use the **Motion MIT core lazily and only in the consoles, never Motion+**. That gives the best fps for the bytes and keeps every dependency OSI. Embeddables use CSS only.
8. **Reduced motion and frame budgets are enforced.** Only transform/opacity are animated, durations stay ≤ 300 ms, and long tasks over 50 ms fail CI. Fluidity has to be measured, not just hoped for.
9. **TanStack Table v9 + TanStack Virtual for every table, with URL-persisted views.** Headless, tree-shakeable, scales to 100k rows, and views are shareable.
10. **Audit log = keyset-cursor infinite query + SSE live tail with a "new events" pill and scroll anchoring.** Real-time without losing the reader's place. SSE works through enterprise proxies.
11. **Charts: uPlot for time series, visx for bespoke gauges and grids. ECharts only lazy-loaded if ever needed.** Smallest and fastest for ops data while staying token-themeable.
12. **Command palette built on Base UI primitives (cmdk-style API), plus a global shortcut registry with a `?` cheat sheet.** Linear-grade keyboard UX without a stale dependency (cmdk's last release was 2025-03), and WCAG 2.1.4 compliant.
13. **SSE as the real-time transport, with events as query invalidations. Defer local-first (TanStack DB / Electric) until 1.0.** Simple, robust, and the cache logic stays in one place.
14. **Embeddables: one React implementation, shipped as `@matura/react` (cascade-layered CSS) and `@matura/elements` (custom elements, Shadow DOM, `::part`, hoisted `@property`).** Parity across stacks. Evaluate a Preact-compat build for size.
15. **Clerk-style `appearance` API (baseTheme/variables/elements/layout/localization) that compiles to our semantic tokens.** It is a proven developer mental model and maps one-to-one onto the DTCG pipeline.
16. **Login via Keycloakify v11 with our own components (no PatternFly).** Per-page code splitting, inlined critical CSS, ≤ 60 KB JS, LCP ≤ 1 s. Brand consistency with the portal, and a fast first impression.
17. **Passkey-first login:** conditional mediation on the username field, a modal "Sign in with passkey" button, and a post-login "create passkey" nudge. Built on Keycloak 26.4+ native passkeys, with no custom authenticator needed.
18. **Replace the Keycloak account console with our portal's "My account"** (via the Account/Admin REST APIs). The KC account theme stays a minimal redirect, so users see one design language.
19. **Performance budgets enforced in CI** (size-limit, Lighthouse CI, Playwright INP traces) **plus web-vitals RUM into our own OTel/console.** Budgets regress unless they are automated, and the RUM data is dogfood for the readiness dashboard.
20. **Fonts: self-hosted Inter Variable (OFL) + Geist Mono (OFL), subsetted, with metric-matched fallbacks. Arabic/Hebrew faces load only for RTL.** Licence-clean, wide script coverage, zero font CLS.
21. **Lingui 6 (ICU, compile-time), with `Intl.*` for formatting.** A single source catalog also generates Keycloak `.properties`. Smallest runtime, translator-friendly ICU, one catalog across all surfaces.
22. **Logical CSS properties only (lint-enforced), `dir`-aware primitives, pseudo-locale + `ar`/`he` in visual tests.** RTL correct by construction.
23. **WCAG 2.2 AA as a release gate** (axe in CI on all stories and flows, manual SR passes, published ACR/VPAT on the trust page). An enterprise procurement requirement, and EAA-relevant.
24. **"Quiet Precision" visual language:** Inter at 13px console body, 4px spacing, radius 8 default, borders over shadows, tinted neutrals, a single brand accent, two density modes, monochrome line illustrations. Linear/Vercel/Stripe-grade calm and density, and trivially re-skinnable.
25. **Storybook 10 + Playwright screenshot regression (git baselines, Docker-pinned) with optional Argos review. No Chromatic, no Lost Pixel (archived).** Fully open-source and self-hostable.

## UI sprint additions

1. **Design-tokens package:** DTCG 2025.10 JSON (reference/semantic/component), Style Dictionary v5 build to CSS vars, Tailwind `@theme`, TS types, Keycloak CSS and email vars.
2. **OKLCH theme generator** (seed → 12-step light/dark ramps), with contrast unit tests, `/t/{tenant}/theme.css` endpoint and ETag caching.
3. **`packages/ui`:** shadcn-pattern components on Base UI (Button, Input, Select, Combobox, Dialog, Sheet, Popover, Menu, Tabs, Toast, Tooltip, Badge, Card, Table shell, Skeleton, EmptyState, Kbd) + React Aria DateRangePicker.
4. **App shell:** Vite 8 + TanStack Router (file routes, intent preload, view transitions, focus/announce on navigation) + Query + React Compiler, sidebar/topbar layout, light/dark/system + density toggles.
5. **Command palette + shortcut registry + `?` cheat sheet.**
6. **DataTable** on TanStack Table v9 + Virtual (server cursor pagination, URL-state filters, column prefs, density, sticky header, a11y semantics).
7. **Audit log viewer:** keyset infinite query, SSE live tail (`Last-Event-ID`), new-events pill, detail sheet with JSON diff, async export.
8. **SSE `/events` multiplexed stream** with BroadcastChannel leader election and query-invalidation protocol.
9. **Chart kit:** uPlot time-series wrapper + visx readiness gauge, control heat grid and sparklines, all token-themed with table fallbacks.
10. **Embeddables v0:** `@matura/react` (MaturaProvider, UserButton, OrgSwitcher, MembersTable) with `appearance` API and cascade layers; `@matura/elements` custom-element wrapper with Shadow DOM, `@property` hoist and `::part`; Preact-compat size spike.
11. **Keycloakify v11 login theme:** login, username, password, OTP, passkey (conditional + modal), register, reset, error and IdP-select pages using `packages/ui`; per-page lazy loading; critical CSS inline; Storybook stories for each page.
12. **"My account" in the portal:** profile, passkeys/MFA devices, sessions, linked IdPs via Account REST API. Minimal redirecting KC account theme.
13. **i18n:** Lingui 6 setup, extraction/compile in CI, lazy catalogs, pseudo-locale, `ar`/`he` RTL, generator for Keycloak `.properties` from the same catalog, stylelint logical-properties rule.
14. **Performance gates:** size-limit per package, Lighthouse CI (login, trust, console route) with budgets, Playwright INP/long-task trace tests, web-vitals RUM → OTel.
15. **Fonts:** self-hosted Inter Variable + Geist Mono subsets, fontaine fallbacks, RTL font loading.
16. **A11y gates:** axe on every story and e2e flow, keyboard-only e2e, focus-ring/target-size lint checks, ACR template.
17. **Storybook 10 + visual regression:** global toolbars (theme/density/locale/brand), Playwright screenshot suite in Docker, Argos (or reg-suit) PR review.
18. **Trust page generator:** static prerender, brandable, controls status feed, print CSS.
19. **Empty-state and illustration set** (~12 SVGs, `currentColor`, permissive licence) + EmptyState component.
20. **Tenant branding editor in the portal:** colour seed, radius, font, logo upload (SVG sanitise / AVIF raster), live preview of login + portal + embeddables, contrast warnings.
