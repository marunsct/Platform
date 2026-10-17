package readiness

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// DocsBase is where each control's guide section lives; the anchor is the control id.
const DocsBase = "https://github.com/marunsct/Platform/blob/main/docs/guide/readiness.md"

// Control is one entry of the catalogue. Installation controls set install; tenant controls set tenant, which
// returns NotApplicable for tenants the control does not cover.
type Control struct {
	ID       string
	Title    string
	Scope    string // installation or tenant
	Public   bool   // shown on the trust page
	Optional bool   // only counted when configured
	Fix      string
	Refs     []Ref
	install  func(Facts) (Status, string)
	tenant   func(Facts, Tenant) (Status, string)
}

const (
	soc2  = "SOC 2"              // AICPA Trust Services Criteria (2017, revised points of focus 2022)
	iso   = "ISO/IEC 27001:2022" // Annex A
	gdpr  = "GDPR"               // Regulation (EU) 2016/679
	scIns = "installation"
	scTen = "tenant"
)

func refs(pairs ...string) []Ref {
	out := make([]Ref, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Ref{Framework: pairs[i], ID: pairs[i+1]})
	}
	return out
}

func check(ok bool, yes, no string) (Status, string) {
	if ok {
		return Pass, yes
	}
	return Fail, no
}

// Catalogue is every control, in report order. Mappings are deliberately conservative: a control is listed against
// a clause only where it is a direct, technical contribution to it.
var Catalogue = []Control{
	{
		ID: "install-kek", Title: "Stored secrets are encrypted under an operator-held key", Scope: scIns, Public: true,
		Fix:  "Set MATURA_KEK to 32 random bytes, base64 (openssl rand -base64 32), and back it up apart from the database.",
		Refs: refs(soc2, "CC6.1", iso, "A.8.24", gdpr, "Art. 32(1)(a)"),
		install: func(f Facts) (Status, string) {
			return check(f.Install.KEKConfigured, "MATURA_KEK is set; secrets are sealed with AES-256-GCM envelope encryption",
				"MATURA_KEK is not set: a random key is used for this run")
		},
	},
	{
		ID: "install-oidc", Title: "People sign in through OpenID Connect", Scope: scIns, Public: true,
		Fix:  "Set MATURA_AUTH=oidc and MATURA_ISSUER to the Keycloak realm URL.",
		Refs: refs(soc2, "CC6.1", iso, "A.8.5"),
		install: func(f Facts) (Status, string) {
			return check(f.Install.Auth == "oidc", "MATURA_AUTH=oidc: bearer tokens are verified against the issuer's keys",
				"MATURA_AUTH="+f.Install.Auth+": request headers are trusted without verification")
		},
	},
	{
		ID: "install-production", Title: "Development mode is off", Scope: scIns, Public: true,
		Fix:  "Set MATURA_ENV=production (or staging for a test installation).",
		Refs: refs(iso, "A.8.31"),
		install: func(f Facts) (Status, string) {
			return check(f.Install.Env != "development", "MATURA_ENV="+f.Install.Env,
				"MATURA_ENV=development: development shortcuts (plain-HTTP webhooks, header sign-in) are allowed")
		},
	},
	{
		ID: "install-tls", Title: "The public address uses HTTPS", Scope: scIns, Public: true,
		Fix:  "Put maturad behind a TLS-terminating proxy and set MATURA_PUBLIC_URL to its https:// address.",
		Refs: refs(soc2, "CC6.7", iso, "A.8.24", gdpr, "Art. 32(1)(a)"),
		install: func(f Facts) (Status, string) {
			u, err := url.Parse(f.Install.PublicURL)
			return check(err == nil && u.Scheme == "https", "MATURA_PUBLIC_URL is "+f.Install.PublicURL,
				"MATURA_PUBLIC_URL is "+f.Install.PublicURL+", not https")
		},
	},
	{
		ID: "install-smtp", Title: "Outgoing email is configured", Scope: scIns,
		Fix: "Set MATURA_SMTP_ADDR (and MATURA_SMTP_FROM, MATURA_SMTP_USER, MATURA_SMTP_PASSWORD) to your mail relay.",
		install: func(f Facts) (Status, string) {
			return check(f.Install.SMTPConfigured, "MATURA_SMTP_ADDR is set; invitation emails are sent",
				"MATURA_SMTP_ADDR is not set: emails are queued but never sent")
		},
	},
	{
		ID: "install-metrics", Title: "Metrics are exported for monitoring", Scope: scIns,
		Fix:  "Set MATURA_METRICS_ADDR (default :9090) and scrape /metrics with Prometheus; alert on webhook and email backlogs.",
		Refs: refs(soc2, "CC7.2", iso, "A.8.16"),
		install: func(f Facts) (Status, string) {
			return check(f.Install.MetricsEnabled, "MATURA_METRICS_ADDR is set: /metrics is served on its own listener",
				"MATURA_METRICS_ADDR is empty: no metrics are exported")
		},
	},
	{
		ID: "install-audit-chain", Title: "The installation audit log verifies", Scope: scIns, Public: true,
		Fix:  "Investigate the first break reported by GET /admin/v1/audit:verify; history was changed outside maturad.",
		Refs: refs(soc2, "CC7.2", iso, "A.8.15"),
		install: func(f Facts) (Status, string) {
			c := f.Installation
			return check(c.OK, fmt.Sprintf("%d events, every hash and link recomputed", c.Events),
				"chain broken: "+c.Reason)
		},
	},
	{
		ID: "install-webhooks", Title: "Webhook deliveries to apps are healthy", Scope: scIns,
		Fix: "Check the failing endpoints (GET /admin/v1/apps/{slug}/webhooks): fix the receiver or its URL, then send a test event.",
		install: func(f Facts) (Status, string) {
			w := f.Webhooks
			if w.Active == 0 {
				return NotApplicable, "no webhook endpoints"
			}
			ev := fmt.Sprintf("%d active endpoints, %d failing, %d events dropped after 24 h in total", w.Active, w.Failing, w.Dropped)
			return check(w.Failing == 0, ev, ev)
		},
	},
	{
		ID: "install-restore-test", Title: "Backups are restored and checked regularly", Scope: scIns, Public: true,
		Fix:  "Run scripts/backup.sh restore-test <dir> --report <maturad URL> weekly (MATURA_TOKEN set to an operator token).",
		Refs: refs(soc2, "A1.3", iso, "A.8.13", gdpr, "Art. 32(1)(c)", gdpr, "Art. 32(1)(d)"),
		install: func(f Facts) (Status, string) {
			return evidenceStatus(f, "restore-test", "restore test")
		},
	},
	{
		ID: "install-access-review", Title: "Access is reviewed at least quarterly", Scope: scIns, Public: true,
		Fix:  "Review operators, tenant owners and admins, then record it: POST /admin/v1/evidence {\"kind\":\"access-review\",\"passed\":true,\"details\":{...}}.",
		Refs: refs(soc2, "CC6.2", soc2, "CC6.3", iso, "A.5.18"),
		install: func(f Facts) (Status, string) {
			return evidenceStatus(f, "access-review", "access review")
		},
	},
	{
		ID: "install-vulnerability-scan", Title: "Images and dependencies are scanned for vulnerabilities", Scope: scIns, Public: true,
		Fix:  "Scan the deployed images (e.g. Trivy or Grype) monthly or on release, then record it: POST /admin/v1/evidence {\"kind\":\"vulnerability-scan\",...}.",
		Refs: refs(soc2, "CC7.1", iso, "A.8.8"),
		install: func(f Facts) (Status, string) {
			return evidenceStatus(f, "vulnerability-scan", "vulnerability scan")
		},
	},
	{
		ID: "tenant-audit-chain", Title: "Every tenant's audit log verifies", Scope: scTen, Public: true,
		Fix:  "Investigate the first break reported by GET /v1/tenants/{tid}/audit:verify; history was changed outside maturad.",
		Refs: refs(soc2, "CC7.2", iso, "A.8.15"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			return check(t.Audit.OK, fmt.Sprintf("%d events verified", t.Audit.Events), "chain broken: "+t.Audit.Reason)
		},
	},
	{
		ID: "tenant-security-policy", Title: "Each organisation has a security policy", Scope: scTen,
		Fix:  "Owners or admins set one in the portal (Security) or with PUT /v1/tenants/{tid}/security-policy.",
		Refs: refs(soc2, "CC6.1"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			if t.Kind == "personal" {
				return NotApplicable, "personal tenant"
			}
			return check(t.PolicySet, "security policy set", "no security policy: installation defaults apply")
		},
	},
	{
		ID: "tenant-mfa", Title: "Organisations require multi-factor authentication", Scope: scTen, Public: true,
		Fix:  "Set require_mfa: true in the tenant's security policy.",
		Refs: refs(soc2, "CC6.1", iso, "A.8.5"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			if t.Kind == "personal" {
				return NotApplicable, "personal tenant"
			}
			return check(t.RequireMFA, "require_mfa is set", "require_mfa is off")
		},
	},
	{
		ID: "tenant-session-limits", Title: "Organisations limit session length and idle time", Scope: scTen,
		Fix:  "Set session_max_age and idle_timeout in the tenant's security policy.",
		Refs: refs(soc2, "CC6.1", iso, "A.8.5"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			if t.Kind == "personal" {
				return NotApplicable, "personal tenant"
			}
			return check(t.SessionMaxAge != nil && t.IdleTimeout != nil, "session_max_age and idle_timeout are set",
				"installation default session limits")
		},
	},
	{
		ID: "tenant-invite-domains", Title: "Company invitations are limited to the company's domains", Scope: scTen,
		Fix:  "Set allowed_email_domains in the tenant's security policy.",
		Refs: refs(soc2, "CC6.2", iso, "A.5.16"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			if t.Kind != "company" {
				return NotApplicable, t.Kind + " tenant"
			}
			return check(t.AllowedEmailDomains > 0, fmt.Sprintf("%d allowed domains", t.AllowedEmailDomains),
				"invitations may go to any address")
		},
	},
	{
		ID: "tenant-audit-streaming", Title: "Company audit logs stream to the company's own systems", Scope: scTen,
		Fix:  "Add an audit destination in the portal (Audit) or with POST /v1/tenants/{tid}/audit/sinks, and keep it delivering.",
		Refs: refs(soc2, "CC7.2", iso, "A.8.15"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			switch {
			case t.Kind != "company":
				return NotApplicable, t.Kind + " tenant"
			case t.SinksFailing > 0:
				return Fail, fmt.Sprintf("%d of %d destinations failing", t.SinksFailing, t.SinksActive+t.SinksFailing)
			}
			return check(t.SinksActive > 0, fmt.Sprintf("%d destinations delivering", t.SinksActive), "no audit destination")
		},
	},
	{
		ID: "tenant-ip-allowlist", Title: "Organisations restrict API access by network (optional)", Scope: scTen,
		Optional: true,
		Fix:      "Optional: set ip_allowlist in the tenant's security policy to its office or VPN ranges.",
		Refs:     refs(soc2, "CC6.6", iso, "A.8.20"),
		tenant: func(_ Facts, t Tenant) (Status, string) {
			if t.IPAllowlist == 0 {
				return NotApplicable, "optional; no allow-list set"
			}
			return Pass, fmt.Sprintf("%d address ranges allowed", t.IPAllowlist)
		},
	},
}

func evidenceStatus(f Facts, kind, name string) (Status, string) {
	e := f.Latest[kind]
	if e == nil {
		return Fail, "no " + name + " recorded"
	}
	day := e.RecordedAt.UTC().Format("2006-01-02")
	window := EvidenceKinds[kind]
	switch {
	case !e.Passed:
		return Fail, "last " + name + " on " + day + " failed"
	case f.Now.Sub(e.RecordedAt) > window:
		return Fail, fmt.Sprintf("last %s passed on %s, more than %d days ago", name, day, int(window/(24*time.Hour)))
	}
	return Pass, fmt.Sprintf("%s passed on %s (%d in the last 90 days)", name, day, f.Recent[kind])
}

func (c Control) evaluate(f Facts) Result {
	res := Result{ID: c.ID, Title: c.Title, Scope: c.Scope, Fix: c.Fix, Docs: DocsBase + "#" + c.ID,
		Public: c.Public, Optional: c.Optional, Refs: c.Refs}
	if res.Refs == nil {
		res.Refs = []Ref{}
	}
	if c.install != nil {
		res.Status, res.Evidence = c.install(f)
		return res
	}
	var failed []string
	applicable := 0
	for _, t := range f.Tenants {
		if t.Status != "active" {
			continue
		}
		st, ev := c.tenant(f, t)
		res.Tenants = append(res.Tenants, TenantResult{TenantID: t.ID, Slug: t.Slug, Status: st, Evidence: ev})
		switch st {
		case Pass:
			applicable++
		case Fail:
			applicable++
			failed = append(failed, t.Slug)
		}
	}
	switch {
	case applicable == 0:
		res.Status, res.Evidence = NotApplicable, "no active tenant this control applies to"
	case len(failed) == 0:
		res.Status, res.Evidence = Pass, fmt.Sprintf("%d of %d tenants", applicable, applicable)
	default:
		names := failed
		if len(names) > 5 {
			names = append(names[:5:5], fmt.Sprintf("and %d more", len(failed)-5))
		}
		res.Status = Fail
		res.Evidence = fmt.Sprintf("%d of %d tenants fail: %s", len(failed), applicable, strings.Join(names, ", "))
	}
	return res
}
