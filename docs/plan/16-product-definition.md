# 16 — Product definition (start here)

*2026-10-11 · written after the owner restated the vision. Where earlier documents disagree, this one wins.*

## 1. The vision in one sentence

**Matura makes any open-source app enterprise-ready.** You add one SDK and a set of self-hosted services, and your
app gets the multi-tenancy, security, audit, backup, privacy and compliance controls that business buyers demand,
plus the evidence to prove it in a security review or audit.

Building a prototype is now easy. Selling it to a business is not, because the buyer asks: *Can we use our own SSO?
Is our data separated from other customers? Who did what, and can we export the log? Are there backups, and have you
tested a restore? Can you delete our data? Do you meet SOC 2 / ISO 27001 / GDPR?* Each answer is weeks of work that
has nothing to do with the app's idea. Matura answers all of them once, for every app.

## 2. What it is not

- **Not a PaaS.** Matura never runs your app. Your app stays wherever you run it: a laptop, a VM, Docker Compose,
  Kubernetes, any cloud. Matura runs next to it as a few services plus an SDK inside the app. (Earlier drafts had an
  app-hosting module; it is dropped. Doc 06 now covers integrating apps, not hosting them.)
- **Not just a login server.** Sign-in is one of nine modules.
- **Not a hosted service.** Everything is open source (Apache-2.0) and self-hosted. Users keep full control: their
  data stays in their own databases, nothing phones home, every piece speaks open standards (OIDC, SAML, SCIM,
  Postgres, S3, CloudEvents), so they can leave at any time.

The analogy: what Stripe did for payments, Matura does for enterprise readiness, but open source and on your own
infrastructure.

## 3. The enterprise checklist, and the module that answers each item

| What a business buyer asks | Module | What the app gets |
|---|---|---|
| "Can our people sign in with our SSO? Is MFA enforced? Are leavers removed automatically?" | **Identity** | sign-up and sign-in, Google/GitHub, MFA and passkeys, per-customer SAML/OIDC SSO and SCIM, sessions (Keycloak underneath) |
| "Is our data separated from other customers?" | **Tenancy** | tenants and workspaces, Postgres row-level security helpers, per-tenant encryption keys, optional dedicated databases |
| "Who can do what?" | **Access** | roles per app, fine-grained permissions (OpenFGA), access reviews, API keys and service accounts |
| "Can we manage our own users and settings?" | **Admin portal** | ready-made customer admin console (members, SSO setup, security policies, audit, API keys) and a platform console for you |
| "Who did what, when? Can we stream it to our SIEM?" | **Audit** | tamper-evident audit log, search, export, SIEM streaming |
| "What if you lose data?" | **Backup** | scheduled and point-in-time backups for the app's Postgres and files, encrypted and immutable, **automatic weekly restore tests**, single-tenant restore; works on Compose/VMs (pgBackRest) and Kubernetes (CloudNativePG) |
| "Can you export or delete our data? Where is it stored?" | **Privacy** | data export and deletion per user and per tenant, retention rules, legal hold, data residency, crypto-shredding |
| "Do you meet SOC 2 / ISO 27001 / GDPR / HIPAA? Fill in our security questionnaire." | **Readiness** (new) | §4 |
| "How many seats and how much usage? Which plan?" | **Entitlements** | plans, limits, usage metering hooks, optional billing |

An app can adopt modules one at a time; Identity + Tenancy + Audit is the usual starting point.

## 4. The Readiness module (the part nobody else ships)

1. **Control packs**: SOC 2, ISO 27001, ISO 42001 (AI management), GDPR, and for AI apps the EU AI Act logging and
   human-oversight duties; HIPAA and others after 1.0. Each control is mapped to the module setting that satisfies it.
2. **`matura check`**: inspects the installation (and optionally the app's repository and deployment) and shows a
   readiness score: which controls are met, which are not, and the exact module or setting that closes each gap.
3. **Continuous evidence**: MFA coverage, SSO and SCIM status, access-review sign-offs, audit-log integrity checks,
   backup and restore-test results, vulnerability scan results, change history. Collected automatically, kept with
   timestamps, exportable as an auditor package.
4. **Documents**: policy templates (information security, access control, incident response, backup, data
   retention), filled in from the actual configuration.
5. **Trust page and questionnaires**: a public trust page the app can host, and pre-filled answers for common
   security questionnaires (CAIQ, SIG Lite style).

Readiness does not replace an auditor and never claims to make anyone compliant; it adds the controls, proves them,
and exports the evidence (OSCAL and JSON) into the compliance tools teams already use: Vanta, Drata, Comp AI, Probo,
CISO Assistant. `matura check` also runs in CI and suggests fixes as pull requests.

## 5. Who else is in this space

| Product | What it covers | Gap Matura fills |
|---|---|---|
| WorkOS, Frontegg, Clerk, Descope, PropelAuth | identity and some admin-portal features | hosted only, priced per feature or connection; no backups, privacy or compliance evidence |
| Keycloak, Zitadel, Logto, Authentik | open-source identity | no customer admin portal, tenancy helpers, backup, audit evidence or readiness |
| Vanta, Drata | compliance evidence and policies | hosted, expensive; they check controls, they do not add them to your app |
| Comp AI (AGPL), Probo, CISO Assistant, Eramba | open-source compliance management | documents and evidence tracking only; the app still has to build every control |
| Ory's enterprise-ready SaaS starter kit | a Next.js template with SSO, directory sync, audit logs | a template you copy for a new app, not a reusable layer for any stack |

**No open-source project both adds the enterprise controls to an app and proves them.** That combination, fully
self-hosted, is the product.

## 6. What AgentCanvas needs from it

AgentCanvas is the first app and the proof. To sell AgentCanvas to businesses it needs, in this order:

1. Identity with SSO, SCIM and MFA (replaces its own OIDC code).
2. Tenancy: workspace columns and row-level security on its tables (AgentCanvas's own T5 work) and per-tenant keys
   (replaces its org data keys).
3. Access: its existing roles (admin, builder, reviewer, viewer) registered with Matura.
4. Admin portal instead of its own members page.
5. Audit: its run and publish events forwarded to the tenant's audit log.
6. Backup: its Postgres and workspace files backed up with restore tests.
7. Privacy: export and delete per tenant.
8. Readiness: SOC 2 / ISO 27001 packs, plus the AI-specific pack (agent actions, human approvals from its inbox,
   model and tool usage logs) that buyers of agent products increasingly ask for.

Later, the agent-identity module (doc 13, M1) lets AgentCanvas agents act on a user's behalf with scoped, audited,
revocable access.

## 7. What this changes in the plan

*Later research (doc 19) added agent identity to 1.0, a performance plan (doc 17) and a UI plan (doc 18).*

- Doc 13: Readiness becomes two sprints inside 1.0; the Backup module must work without Kubernetes; app hosting is
  dropped (not just postponed). Kubernetes Helm charts remain only as one way to install Matura itself.
- Docs 00, 06, README: wording aligned with this definition.
- Renamed from "Tenantry" (which sounded like tenancy only) to **Matura**, Latin for "ripe": the app matures from
  prototype to market-ready (doc 14, decision 2).
