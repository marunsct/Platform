// Package readiness evaluates an installation's controls against its real state and reports the gaps
// (TS24, technical specification §15). It never claims compliance: a passing control is evidence that a setting is
// in place, not an audit opinion.
package readiness

import (
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
)

// Notice goes with every report and trust page.
const Notice = "Readiness shows which controls are in place on this installation and the evidence for them. " +
	"It is not an audit and does not certify compliance with any framework; mappings are indicative and an " +
	"auditor decides."

// Install is what maturad knows about its own configuration.
type Install struct {
	Product         string
	Env             string // development, staging, production
	Auth            string // oidc or dev
	KEKConfigured   bool   // MATURA_KEK set (not a random key for the run)
	SMTPConfigured  bool
	MetricsEnabled  bool
	PublicURL       string
	TrustPage       bool
	SecurityContact string
}

// Chain is the result of verifying one audit hash chain.
type Chain struct {
	OK     bool
	Events int64
	Reason string // first break, when not OK
}

// Tenant is one tenant's posture.
type Tenant struct {
	ID                  uuid.UUID
	Slug                string
	Kind                string // company, shared, personal
	Status              string
	PolicySet           bool
	RequireMFA          bool
	SessionMaxAge       *int
	IdleTimeout         *int
	AllowedEmailDomains int
	IPAllowlist         int
	SinksActive         int // audit destinations delivering
	SinksFailing        int
	Audit               Chain
}

// Webhooks sums up the app webhook endpoints.
type Webhooks struct {
	Active   int   // not disabled
	Failing  int   // in the failing state
	Dropped  int64 // events given up on after 24 hours, over all endpoints
	Disabled int
}

// Evidence is one recorded piece of evidence (POST /admin/v1/evidence), kept in the installation audit chain.
type Evidence struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Passed     bool            `json:"passed"`
	Details    json.RawMessage `json:"details"`
	RecordedAt time.Time       `json:"recorded_at"`
	RecordedBy string          `json:"recorded_by"`
	Seq        int64           `json:"seq"`  // position in the installation audit chain
	Hash       string          `json:"hash"` // the audit event's hash
}

// EvidenceKinds are the kinds POST /admin/v1/evidence accepts, with how long one stays current.
var EvidenceKinds = map[string]time.Duration{
	"restore-test":       35 * 24 * time.Hour,
	"vulnerability-scan": 35 * 24 * time.Hour,
	"access-review":      92 * 24 * time.Hour,
}

// Facts is everything the controls are evaluated against.
type Facts struct {
	Now          time.Time
	Install      Install
	Installation Chain // the installation audit chain
	Tenants      []Tenant
	Webhooks     Webhooks
	Latest       map[string]*Evidence // newest evidence of each kind
	Recent       map[string]int       // evidence of each kind in the last 90 days
}

type Status string

const (
	Pass          Status = "pass"
	Fail          Status = "fail"
	NotApplicable Status = "not-applicable"
)

// Ref is a framework clause a control contributes to.
type Ref struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

// Result is one control evaluated.
type Result struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Scope    string         `json:"scope"` // installation or tenant
	Status   Status         `json:"status"`
	Evidence string         `json:"evidence"`
	Fix      string         `json:"fix"`
	Docs     string         `json:"docs"`
	Public   bool           `json:"public"`
	Optional bool           `json:"optional"`
	Refs     []Ref          `json:"refs"`
	Tenants  []TenantResult `json:"tenants,omitempty"`
}

type TenantResult struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Slug     string    `json:"slug"`
	Status   Status    `json:"status"`
	Evidence string    `json:"evidence"`
}

// Summary holds the settings policy templates are filled from.
type Summary struct {
	Product              string     `json:"product"`
	PublicURL            string     `json:"public_url"`
	Environment          string     `json:"environment"`
	Auth                 string     `json:"auth"`
	Tenants              int        `json:"tenants"` // active tenants
	TenantsMFA           int        `json:"tenants_mfa"`
	TenantsSessionLimits int        `json:"tenants_session_limits"`
	TenantsDomains       int        `json:"tenants_domain_restricted"`
	TenantsIPAllowlist   int        `json:"tenants_ip_allowlist"`
	TenantsAuditStream   int        `json:"tenants_audit_streaming"`
	AuditChains          int        `json:"audit_chains"`
	AuditChainsOK        int        `json:"audit_chains_verified"`
	LastRestoreTest      *time.Time `json:"last_restore_test"`
	LastRestorePassed    bool       `json:"last_restore_test_passed"`
	RestoreTests90d      int        `json:"restore_tests_90d"`
	LastAccessReview     *time.Time `json:"last_access_review"`
	LastVulnScan         *time.Time `json:"last_vulnerability_scan"`
}

// Report is the answer of GET /admin/v1/readiness.
type Report struct {
	GeneratedAt   time.Time `json:"generated_at"`
	Product       string    `json:"product"`
	Notice        string    `json:"notice"`
	Score         float64   `json:"score"` // percent of applicable controls that pass, one decimal
	Passed        int       `json:"passed"`
	Failed        int       `json:"failed"`
	NotApplicable int       `json:"not_applicable"`
	Controls      []Result  `json:"controls"`
	Summary       Summary   `json:"summary"`
}

// Evaluate runs every control in the catalogue against the facts.
func Evaluate(f Facts) Report {
	r := Report{GeneratedAt: f.Now.UTC(), Product: f.Install.Product, Notice: Notice, Controls: []Result{}}
	for _, c := range Catalogue {
		res := c.evaluate(f)
		switch res.Status {
		case Pass:
			r.Passed++
		case Fail:
			r.Failed++
		default:
			r.NotApplicable++
		}
		r.Controls = append(r.Controls, res)
	}
	r.Score = Score(r.Passed, r.Passed+r.Failed)
	r.Summary = summarise(f)
	return r
}

// Score is passed/applicable as a percentage with one decimal; 0 when nothing applies.
func Score(passed, applicable int) float64 {
	if applicable == 0 {
		return 0
	}
	return math.Round(1000*float64(passed)/float64(applicable)) / 10
}

func summarise(f Facts) Summary {
	s := Summary{Product: f.Install.Product, PublicURL: f.Install.PublicURL, Environment: f.Install.Env,
		Auth: f.Install.Auth, AuditChains: 1}
	if f.Installation.OK {
		s.AuditChainsOK++
	}
	for _, t := range f.Tenants {
		if t.Status != "active" {
			continue
		}
		s.Tenants++
		s.AuditChains++
		if t.Audit.OK {
			s.AuditChainsOK++
		}
		if t.RequireMFA {
			s.TenantsMFA++
		}
		if t.SessionMaxAge != nil && t.IdleTimeout != nil {
			s.TenantsSessionLimits++
		}
		if t.AllowedEmailDomains > 0 {
			s.TenantsDomains++
		}
		if t.IPAllowlist > 0 {
			s.TenantsIPAllowlist++
		}
		if t.SinksActive > 0 && t.SinksFailing == 0 {
			s.TenantsAuditStream++
		}
	}
	if e := f.Latest["restore-test"]; e != nil {
		at := e.RecordedAt
		s.LastRestoreTest, s.LastRestorePassed = &at, e.Passed
	}
	s.RestoreTests90d = f.Recent["restore-test"]
	if e := f.Latest["access-review"]; e != nil {
		at := e.RecordedAt
		s.LastAccessReview = &at
	}
	if e := f.Latest["vulnerability-scan"]; e != nil {
		at := e.RecordedAt
		s.LastVulnScan = &at
	}
	return s
}
