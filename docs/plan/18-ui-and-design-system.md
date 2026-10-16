# 18 — UI and design system

*2026-10-11 · distilled from [research/ui.md](../research/ui.md), which has versions, licences, sources and the
full reasoning. Where doc 05 disagrees with this document, this one wins.*

## 1. Goal

Every screen Matura puts in front of a person (sign-in, the customer admin portal, the operator console, the widgets
apps embed, the public trust page) should feel as calm, fast and fluid as Linear, Vercel or Stripe, while carrying
each app's and each customer's brand, working in every language including right-to-left ones, and meeting WCAG 2.2 AA.
Every dependency is OSI open source.

## 2. Surfaces

| Surface | Built with | Budget |
|---|---|---|
| Sign-in, sign-up, MFA, passkeys | Keycloakify 11 using Matura's own components (no PatternFly), passkey-first | ≤ 60 KB JS, LCP ≤ 1 s |
| Customer admin portal (members, roles, SSO/SCIM wizard, policies, audit, API keys, plans, privacy, branding, My account) | React SPA (§3) | cold load LCP ≤ 1.8 s, route JS ≤ 170 KB gz |
| Operator console (tenants, health, readiness, evidence, backups) | same app shell and components | same |
| Embeddable widgets (`UserButton`, `OrgSwitcher`, `MembersTable`, `AuditLog`, `SSOSetup`, `ApiKeys`, `SecuritySettings`) | `@matura/react` plus `@matura/elements` custom elements for non-React apps | core ≤ 25 KB gz excluding React |
| Trust page | prerendered static HTML, regenerated on publish | ~0 KB JS, LCP ≤ 1 s |

Keycloak's own account console is replaced by "My account" in the portal, so users see one design language.

## 3. Decisions

1. **React 19 + Vite as static single-page apps**, with TanStack Router and Query and React Compiler. The consoles sit
   behind sign-in, so server rendering adds little, and static files mean self-hosters never run or patch a Node
   server (the React server-components code path had a severity-10 remote code execution bug, CVE-2025-55182, in
   December 2025). TanStack Start stays an upgrade path on the same router.
2. **Owned components in the shadcn/ui pattern on Base UI (MIT).** The source lives in `packages/ui`, so the look is
   fully ours. React Aria Components only for date and time pickers, for their locale and right-to-left quality.
3. **One token pipeline.** Design tokens in the W3C DTCG 2025.10 format, built with Style Dictionary into CSS
   variables, the Tailwind CSS 4 theme, TypeScript types, the Keycloak theme and email templates.
4. **White-label that stays accessible.** A tenant picks a brand colour; Matura generates 12-step OKLCH light and dark
   scales and enforces contrast in code, so no tenant can ship an unreadable theme. Tenants change only brand colour,
   neutral tint, radius, font, density and logo. Each tenant's theme is served as a cached `theme.css`: no flash of
   the wrong theme, no JavaScript.
5. **Motion is CSS first:** View Transitions for route and list changes, `@starting-style` for enter animations, spring
   curves via `linear()`. The Motion library (MIT core only) loads lazily in the consoles for gestures; the embeddables
   use CSS only. Only transform and opacity animate, durations stay at or under 300 ms, `prefers-reduced-motion` is
   honoured, and any task over 50 ms fails CI.
6. **Optimistic by default.** Mutations update the screen immediately and roll back on error; skeletons match final
   layout so nothing shifts (CLS ≤ 0.05); routes preload on hover and focus.
7. **Data-heavy views:** every table uses TanStack Table and TanStack Virtual with server cursor pagination and filters
   saved in the URL. The audit log is an infinite list with a live tail over server-sent events, a "new events" pill
   and scroll anchoring, so readers never lose their place.
8. **Charts:** uPlot for time series, visx for the readiness gauge, control heat grid and sparklines, all themed by
   tokens and each with a table fallback for screen readers.
9. **Keyboard first:** a command palette on Base UI, a shortcut registry and a `?` cheat sheet.
10. **Real time over server-sent events** carrying cache-invalidation messages; one shared connection per browser via
    BroadcastChannel. Local-first sync (TanStack DB, ElectricSQL) waits until those projects reach 1.0.
11. **Embeddables:** one React implementation shipped twice: `@matura/react` with CSS in cascade layers (host CSS
    always wins), and `@matura/elements`, custom elements with Shadow DOM and `::part`. A Clerk-style `appearance` prop
    (base theme, variables, elements, layout, localization) compiles into the same tokens. Widgets authenticate with a
    short-lived token and an origin allow-list.
12. **Passkey-first sign-in:** conditional mediation on the username field (the browser offers saved passkeys),
    a "Sign in with passkey" button, and a nudge to create a passkey after a password sign-in. This also helps doc 17,
    since password logins are Keycloak's most expensive operation.
13. **Visual language "Quiet Precision":** Inter Variable (13 px console body) and Geist Mono, a 4 px spacing grid,
    8 px default radius, borders rather than shadows, neutrals tinted with the brand hue, one accent colour,
    comfortable and compact density modes, monochrome line illustrations for empty states, light, dark and system
    themes. Fonts are self-hosted, subsetted and paired with metric-matched fallbacks; Arabic and Hebrew faces load
    only for those locales. Icons: Lucide.
14. **Languages:** Lingui (ICU messages, compiled), one catalogue that also generates Keycloak's message files;
    logical CSS properties only, enforced by lint; Arabic, Hebrew and a pseudo-locale in visual tests.
15. **Accessibility is a release gate:** axe on every story and end-to-end flow, keyboard-only tests, manual screen
    reader passes, and a published accessibility conformance report on the trust page.
16. **Quality gates in CI:** size-limit per package, Lighthouse CI on sign-in, trust page and a console route,
    Playwright traces for INP and long tasks, real-user Web Vitals sent to Matura's own OpenTelemetry pipeline, Storybook
    with Playwright screenshot regression (Argos or reg-suit for review; no proprietary services).

## 4. Targets

| Metric | Sign-in and trust page | Consoles |
|---|---|---|
| Largest Contentful Paint | ≤ 1.0 s | ≤ 1.8 s cold, instant on cached navigation |
| Interaction to Next Paint (p75) | ≤ 100 ms | ≤ 150 ms |
| Cumulative Layout Shift | ≤ 0.05 | ≤ 0.05 |
| Frame rate during animation | 60 fps, 120 fps where the display allows | same |
| Lighthouse accessibility | 100 | 100 |

## 5. Where this lands in the roadmap

Doc 13 adds sprint **TS3 Design system and app shell** before any UI work, so sign-in (TS4), the SDK widgets (TS7)
and the consoles (TS8–TS10) all build on the same components and gates. The branding editor, audit live tail and
My account land in TS9; the trust page generator in TS25.

## 6. Still to verify

TanStack Start 1.0 status, the date shadcn/ui made Base UI its default, React 19.3 `<ViewTransition>` details,
Firefox support for cross-document view transitions, and whether Keycloak offers passkey creation after password
sign-in natively. TS3 checks each before relying on it.
