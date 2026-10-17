# Readiness: controls, evidence, trust page and policy templates

Readiness tells an operator which security controls are in place on their Matura installation, shows the evidence
for each, and lists every gap with the setting or step that closes it. It is computed from the installation's real
state each time it is asked for, not from a questionnaire.

**What it is not.** Readiness is not an audit, a certification or an attestation. A passing control means a setting
is in place and Matura could see evidence for it; it does not mean a framework's requirement is met. The framework
references (SOC 2, ISO/IEC 27001:2022, GDPR) are indicative pointers to where a control helps, kept deliberately
narrow. Organisational controls (training, vendor management, HR, risk assessment) are outside what software can
see, and an auditor decides.

## Running a check

`matura check` asks maturad for its readiness report (`GET /admin/v1/readiness`) as an operator:

```sh
go build -o matura ./cmd/matura
export MATURA_URL=https://matura.example.com     # default http://localhost:8080
export MATURA_TOKEN=<an operator's access token>  # a token with the operator realm role
matura check                                      # table of controls, then each gap with its fix and docs link
matura check --json                               # the report as JSON
matura check --oscal > readiness.oscal.json       # OSCAL 1.1.2 assessment results
matura check --min-score 80                       # exit 1 when the score is below 80 %
```

On a development install (`MATURA_AUTH=dev`) set `MATURA_DEV_USER` to any UUID instead of a token.

| Exit status | Meaning |
|---|---|
| 0 | report printed, score at or above `--min-score` |
| 1 | score below `--min-score` |
| 2 | usage error, maturad unreachable, or not signed in as an operator |

The **score** is passed controls ÷ applicable controls, in percent with one decimal. A control is *not applicable*
when there is nothing for it to check (no tenants yet, no webhook endpoints, a personal tenant) and does not count
either way. Optional controls count only once configured.

In CI, run it against staging after each deploy so a regression in configuration fails the pipeline:

```sh
MATURA_URL=$STAGING_URL MATURA_TOKEN=$OPERATOR_TOKEN matura check --min-score 90
```

### What maturad looks at

Each report re-reads: maturad's configuration (`MATURA_ENV`, `MATURA_AUTH`, `MATURA_KEK`, `MATURA_SMTP_ADDR`,
`MATURA_METRICS_ADDR`, `MATURA_PUBLIC_URL`); every active tenant's security policy and audit destinations; every
audit hash chain, recomputed from the first event (the installation chain and one per active tenant); the app
webhook endpoints; and the newest evidence of each kind. Verifying chains reads the whole audit log, so a report on
a large installation takes a while; the trust page keeps its result for five minutes.

## Controls

| Id | Control | Scope | Public | SOC 2 | ISO/IEC 27001:2022 | GDPR |
|---|---|---|---|---|---|---|
| [install-kek](#install-kek) | Stored secrets are encrypted under an operator-held key | installation | yes | CC6.1 | A.8.24 | Art. 32(1)(a) |
| [install-oidc](#install-oidc) | People sign in through OpenID Connect | installation | yes | CC6.1 | A.8.5 | |
| [install-production](#install-production) | Development mode is off | installation | yes | | A.8.31 | |
| [install-tls](#install-tls) | The public address uses HTTPS | installation | yes | CC6.7 | A.8.24 | Art. 32(1)(a) |
| [install-smtp](#install-smtp) | Outgoing email is configured | installation | | | | |
| [install-metrics](#install-metrics) | Metrics are exported for monitoring | installation | | CC7.2 | A.8.16 | |
| [install-audit-chain](#install-audit-chain) | The installation audit log verifies | installation | yes | CC7.2 | A.8.15 | |
| [install-webhooks](#install-webhooks) | Webhook deliveries to apps are healthy | installation | | | | |
| [install-restore-test](#install-restore-test) | Backups are restored and checked regularly | installation | yes | A1.3 | A.8.13 | Art. 32(1)(c), 32(1)(d) |
| [install-access-review](#install-access-review) | Access is reviewed at least quarterly | installation | yes | CC6.2, CC6.3 | A.5.18 | |
| [install-vulnerability-scan](#install-vulnerability-scan) | Images and dependencies are scanned for vulnerabilities | installation | yes | CC7.1 | A.8.8 | |
| [tenant-audit-chain](#tenant-audit-chain) | Every tenant's audit log verifies | tenant | yes | CC7.2 | A.8.15 | |
| [tenant-security-policy](#tenant-security-policy) | Each organisation has a security policy | tenant | | CC6.1 | | |
| [tenant-mfa](#tenant-mfa) | Organisations require multi-factor authentication | tenant | yes | CC6.1 | A.8.5 | |
| [tenant-session-limits](#tenant-session-limits) | Organisations limit session length and idle time | tenant | | CC6.1 | A.8.5 | |
| [tenant-invite-domains](#tenant-invite-domains) | Company invitations are limited to the company's domains | tenant | | CC6.2 | A.5.16 | |
| [tenant-audit-streaming](#tenant-audit-streaming) | Company audit logs stream to the company's own systems | tenant | | CC7.2 | A.8.15 | |
| [tenant-ip-allowlist](#tenant-ip-allowlist) | Organisations restrict API access by network (optional) | tenant | | CC6.6 | A.8.20 | |

Tenant controls are evaluated for every **active** tenant they apply to and pass only when all of them pass; the
report lists each tenant's result, and the evidence names up to five failing tenants. The catalogue is
`internal/readiness/controls.go`.

### install-kek

Passes when `MATURA_KEK` is set. Without it (development only) maturad seals secrets with a random key for the run.
Fix: `openssl rand -base64 32` into `MATURA_KEK`, and back the key up apart from the database backups.

### install-oidc

Passes when `MATURA_AUTH=oidc`. `dev` trusts `X-Matura-Dev-*` headers. Fix: `MATURA_AUTH=oidc` with `MATURA_ISSUER`.

### install-production

Passes unless `MATURA_ENV=development`, which allows plain-HTTP webhooks and header sign-in. Fix: `MATURA_ENV=production`.

### install-tls

Passes when `MATURA_PUBLIC_URL` starts with `https://`. maturad does not terminate TLS itself; put it behind a proxy
that does, and set the public URL to that address. This checks the configured address, not the proxy's TLS settings.

### install-smtp

Passes when `MATURA_SMTP_ADDR` is set; otherwise invitation emails are queued and never sent. Not mapped to a
framework: it is operational.

### install-metrics

Passes when `MATURA_METRICS_ADDR` is not empty. Scrape `/metrics` and alert on the webhook and email backlogs.

### install-audit-chain

Recomputes every hash of the installation chain (apps, roles, plans, operator actions, evidence) and checks the
links and the head (technical specification §13.2). A failure names the first break; history was changed outside
maturad, which only a database superuser or the owner role can do.

### install-webhooks

Passes when no app webhook endpoint is in the `failing` state; not applicable without endpoints. The evidence also
counts events dropped after 24 hours (apps catch up from the change feed). Not mapped: it is operational.

### install-restore-test

Passes when the newest restore-test evidence passed and is at most 35 days old. Run
`scripts/backup.sh restore-test <dir> --report <maturad URL>` weekly with `MATURA_TOKEN` set: the script restores
into throwaway databases, compares row counts and posts the result (passed or failed, with per-database details) to
`POST /admin/v1/evidence`. See [backups](backup.md).

### install-access-review

Passes when an access review passed in the last 92 days. Review installation operators and each organisation's
owners and admins, then record it:

```sh
curl -X POST "$MATURA_URL/admin/v1/evidence" -H "Authorization: Bearer $MATURA_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"access-review","passed":true,"details":{"reviewer":"jane@acme.example","removed":2}}'
```

### install-vulnerability-scan

Passes when a vulnerability scan passed in the last 35 days. Scan the deployed images (Trivy, Grype) on each release
and at least monthly, and record it with `kind: vulnerability-scan` (put the scanner, image digests and counts by
severity in `details`). "Passed" is your judgement against your own remediation SLAs.

### tenant-audit-chain

The same verification for each active tenant's chain.

### tenant-security-policy

Passes when a company or shared tenant has saved a security policy (personal tenants are not applicable).

### tenant-mfa

Passes when the tenant's policy has `require_mfa: true`. Keycloak enforces it at sign-in (TS12): Matura's realm
flows run the extension's `matura-mfa-policy` authenticator, which challenges members who have a second factor and
makes members without one enrol TOTP before the sign-in finishes (password and social sign-ins; with the tenant's own
SSO, MFA is the customer IdP's job). The control checks the setting, not how many members have enrolled, and it
assumes Keycloak runs Matura's realm flows and extension.

### tenant-session-limits

Passes when the policy sets both `session_max_age` and `idle_timeout`. They are enforced when an app asks for a
token (TS12): Matura's token mapper sends the Keycloak session's age and idle time, maturad refuses a session past
either limit with `session_expired`, and the mapper ends that session so the person signs in again.

### tenant-invite-domains

Company tenants only: passes when `allowed_email_domains` is not empty, which maturad enforces on new invitations.

### tenant-audit-streaming

Company tenants only: passes when at least one audit destination is delivering and none is failing.

### tenant-ip-allowlist

Optional: passes when the tenant set `ip_allowlist`; a tenant without one is not applicable rather than failing.

## Evidence

`POST /admin/v1/evidence` (operators) records evidence of kind `restore-test`, `access-review` or
`vulnerability-scan` with `passed` and optional `details` (a JSON object up to 16 KiB). It is written to the
installation audit chain as action `evidence.<kind>`, so it is hash-chained and cannot be changed or deleted
through maturad. `GET /admin/v1/evidence?kind=` lists it newest first. Restore tests and scans stay current for 35
days, access reviews for 92.

## OSCAL and JSON export

`matura check --oscal` writes a minimal OSCAL 1.1.2 *assessment results* document: one result, one observation per
control (its evidence, status and framework references as props, a link to this guide) and one finding per applicable
control with target status `satisfied` or `not-satisfied`. UUIDs are derived from the report, so the same report
gives the same document. The output validates against NIST's published JSON schema for assessment results; it has
not yet been imported into each GRC tool (Vanta, Drata, Comp AI, Probo, CISO Assistant), and its `import-ap` points
to this guide rather than a full OSCAL assessment plan. `--json` is the report exactly as the API returns it.

## Trust page

maturad can serve a public trust page at `/trust` (and `/trust.json`) showing the installation's posture from the
controls marked *public* above: each one's title, whether it is in place, and its framework references.

It is **off by default** (privacy: a public page tells anyone which controls are missing). Turn it on with:

| Variable | Meaning |
|---|---|
| `MATURA_TRUST_PAGE` | `on` serves `/trust` and `/trust.json`; `off` (default) answers 404 |
| `MATURA_PRODUCT_NAME` | name on the page and in reports (default `Matura`) |
| `MATURA_SECURITY_CONTACT` | optional address shown for security reports |

What it never shows: evidence text, tenant names or slugs, per-tenant results, settings values, non-public controls.
The page is plain HTML with no scripts, one inline stylesheet allowed by its hash in a strict
Content-Security-Policy (`default-src 'none'`, `script-src 'none'`, `frame-ancestors 'none'`), light and dark
themes from the system setting, and `Cache-Control: public, max-age=300`. maturad renders it on the first request
and keeps the result for five minutes (evidence recorded through that replica renders it again at once), so it is cheap to serve. Link it from
your own site, or put a CDN in front of it.

## Policy templates

[`docs/templates`](../templates/README.md) holds three templates: access control, incident response and backup.
They are marked as templates; adopting one means reviewing, changing and approving it. `matura check` fills the
placeholders it can from the report and leaves the rest:

```sh
matura check --policies docs/templates --out policies \
  --set organisation="Acme Ltd" --set policy_owner="Head of Engineering" --set backup_frequency=daily
```

It writes each filled template to `--out` (default `./policies`) and lists the placeholders still open per file.
`--set key=value` supplies or overrides any placeholder.

| Placeholder | Filled from |
|---|---|
| `product_name`, `public_url` | `MATURA_PRODUCT_NAME`, `MATURA_PUBLIC_URL` |
| `generated_at`, `readiness_score` | the report |
| `sign_in_method` | `MATURA_AUTH` |
| `mfa_requirement`, `tenants`, `tenants_mfa`, `tenants_session_limits`, `tenants_domain_restricted`, `tenants_ip_allowlist`, `tenants_audit_streaming` | active tenants' security policies and audit destinations |
| `audit_chains`, `audit_chains_verified`, `audit_retention` | audit verification |
| `last_restore_test`, `last_restore_test_result`, `restore_tests_90d` | restore-test evidence |
| `last_access_review`, `last_vulnerability_scan` | evidence |
| `control_<id>` (dashes as underscores, e.g. `control_tenant_mfa`) | each control's status |
| `organisation`, `policy_owner`, `approver`, `effective_date`, `review_cycle`, `leaver_sla`, `access_review_cycle`, `incident_contact`, `incident_lead`, `communications_lead`, `sev1_response`, `sev2_response`, `review_window`, `record_retention`, `backup_frequency`, `backup_retention`, `backup_location`, `rpo`, `rto`, `restore_test_frequency`, `backup_admins` | `--set` only: organisational choices |

## Not built yet

Control packs for ISO/IEC 42001 and the EU AI Act, opening fix pull requests, MFA coverage measured from Keycloak
(rather than the policy setting), SSO and SCIM status, the SIG Lite and CAIQ answer banks, the generated security
whitepaper, and readiness views in the consoles (doc 13 TS24, TS25).
