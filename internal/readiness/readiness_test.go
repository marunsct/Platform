package readiness

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func ptr(i int) *int { return &i }

func devFacts() Facts {
	return Facts{Now: now, Install: Install{Product: "Matura", Env: "development", Auth: "dev",
		PublicURL: "http://localhost:8080", MetricsEnabled: true},
		Installation: Chain{OK: true, Events: 3},
		Latest:       map[string]*Evidence{}, Recent: map[string]int{}}
}

func prodFacts() Facts {
	f := Facts{Now: now, Install: Install{Product: "Acme", Env: "production", Auth: "oidc", KEKConfigured: true, TenantKeys: true,
		SMTPConfigured: true, MetricsEnabled: true, PublicURL: "https://id.acme.example"},
		Installation: Chain{OK: true, Events: 40},
		Webhooks:     Webhooks{Active: 2},
		Latest:       map[string]*Evidence{}, Recent: map[string]int{}}
	for kind := range EvidenceKinds {
		f.Latest[kind] = &Evidence{Kind: kind, Passed: true, RecordedAt: now.Add(-48 * time.Hour)}
		f.Recent[kind] = 4
	}
	f.Tenants = []Tenant{{ID: uuid.New(), Slug: "acme", Kind: "company", Status: "active", PolicySet: true,
		RequireMFA: true, SessionMaxAge: ptr(28800), IdleTimeout: ptr(1800), AllowedEmailDomains: 1, SinksActive: 1,
		Audit: Chain{OK: true, Events: 12}}}
	return f
}

func byID(r Report) map[string]Result {
	out := map[string]Result{}
	for _, c := range r.Controls {
		out[c.ID] = c
	}
	return out
}

func TestDevInstallFailsTheProductionControls(t *testing.T) {
	r := Evaluate(devFacts())
	got := byID(r)
	for _, id := range []string{"install-kek", "install-oidc", "install-production", "install-tls", "install-smtp",
		"install-restore-test", "install-access-review", "install-vulnerability-scan"} {
		if got[id].Status != Fail {
			t.Errorf("%s: %s (%s), want fail", id, got[id].Status, got[id].Evidence)
		}
	}
	for _, id := range []string{"install-metrics", "install-audit-chain"} {
		if got[id].Status != Pass {
			t.Errorf("%s: %s, want pass", id, got[id].Status)
		}
	}
	// no tenants and no webhooks: those controls do not apply and do not count
	for _, id := range []string{"install-webhooks", "tenant-mfa", "tenant-audit-chain", "tenant-ip-allowlist"} {
		if got[id].Status != NotApplicable {
			t.Errorf("%s: %s, want not-applicable", id, got[id].Status)
		}
	}
	if r.Passed != 2 || r.Failed != 9 || r.Score != 18.2 {
		t.Fatalf("score %v (%d passed, %d failed)", r.Score, r.Passed, r.Failed)
	}
	for _, c := range r.Controls {
		if c.Fix == "" || !strings.HasSuffix(c.Docs, "#"+c.ID) {
			t.Errorf("%s: missing fix or docs link", c.ID)
		}
	}
}

func TestProductionInstallPasses(t *testing.T) {
	r := Evaluate(prodFacts())
	for _, c := range r.Controls {
		if c.Status == Fail {
			t.Errorf("%s fails: %s", c.ID, c.Evidence)
		}
	}
	if r.Score != 100 || byID(r)["tenant-ip-allowlist"].Status != NotApplicable {
		t.Fatalf("score %v; ip allow-list %s", r.Score, byID(r)["tenant-ip-allowlist"].Status)
	}
	if r.Summary.Tenants != 1 || r.Summary.TenantsMFA != 1 || r.Summary.AuditChainsOK != 2 || r.Summary.LastRestoreTest == nil {
		t.Fatalf("summary %+v", r.Summary)
	}
}

func TestTenantControlsAggregate(t *testing.T) {
	f := prodFacts()
	f.Tenants = append(f.Tenants,
		Tenant{ID: uuid.New(), Slug: "globex", Kind: "company", Status: "active", Audit: Chain{OK: false, Reason: "seq 4: hash does not match"},
			SinksActive: 1, SinksFailing: 1, IPAllowlist: 2},
		Tenant{ID: uuid.New(), Slug: "solo", Kind: "personal", Status: "active", Audit: Chain{OK: true}},
		Tenant{ID: uuid.New(), Slug: "gone", Kind: "company", Status: "suspended"})
	got := byID(Evaluate(f))
	mfa := got["tenant-mfa"]
	if mfa.Status != Fail || mfa.Evidence != "1 of 2 tenants fail: globex" || len(mfa.Tenants) != 3 {
		t.Fatalf("tenant-mfa: %s %q %d tenants", mfa.Status, mfa.Evidence, len(mfa.Tenants))
	}
	if got["tenant-audit-chain"].Status != Fail || got["tenant-audit-streaming"].Status != Fail {
		t.Fatal("broken chain or failing destination passed")
	}
	if ip := got["tenant-ip-allowlist"]; ip.Status != Pass || ip.Evidence != "1 of 1 tenants" {
		t.Fatalf("optional allow-list: %s %q", ip.Status, ip.Evidence)
	}
}

func TestEvidenceFreshness(t *testing.T) {
	f := prodFacts()
	f.Latest["restore-test"] = &Evidence{Passed: true, RecordedAt: now.Add(-40 * 24 * time.Hour)}
	f.Latest["access-review"] = &Evidence{Passed: false, RecordedAt: now.Add(-time.Hour)}
	delete(f.Latest, "vulnerability-scan")
	got := byID(Evaluate(f))
	if c := got["install-restore-test"]; c.Status != Fail || !strings.Contains(c.Evidence, "more than 35 days ago") {
		t.Errorf("stale restore test: %s %q", c.Status, c.Evidence)
	}
	if c := got["install-access-review"]; c.Status != Fail || !strings.Contains(c.Evidence, "failed") {
		t.Errorf("failed review: %s %q", c.Status, c.Evidence)
	}
	if c := got["install-vulnerability-scan"]; c.Status != Fail || c.Evidence != "no vulnerability scan recorded" {
		t.Errorf("missing scan: %s %q", c.Status, c.Evidence)
	}
}

func TestPublicViewHidesDetails(t *testing.T) {
	f := prodFacts()
	f.Tenants[0].RequireMFA = false
	tr := Public(Evaluate(f), "security@acme.example")
	raw, _ := json.Marshal(tr)
	if strings.Contains(string(raw), "acme\"") || strings.Contains(string(raw), `"evidence":`) {
		t.Fatalf("public view leaks tenant or evidence: %s", raw)
	}
	for _, c := range tr.Controls {
		ctl := byID(Evaluate(f))[c.ID]
		if !ctl.Public {
			t.Errorf("%s is not public", c.ID)
		}
	}
	if tr.Applicable == 0 || tr.InPlace != tr.Applicable-1 {
		t.Fatalf("in place %d of %d", tr.InPlace, tr.Applicable)
	}
}

func TestMappingsUseKnownFrameworks(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Catalogue {
		if seen[c.ID] {
			t.Errorf("duplicate id %s", c.ID)
		}
		seen[c.ID] = true
		if (c.install == nil) == (c.tenant == nil) {
			t.Errorf("%s: needs exactly one of install and tenant", c.ID)
		}
		for _, r := range c.Refs {
			ok := false
			switch r.Framework {
			case soc2:
				ok = strings.HasPrefix(r.ID, "CC") || strings.HasPrefix(r.ID, "A1.")
			case iso:
				ok = strings.HasPrefix(r.ID, "A.5.") || strings.HasPrefix(r.ID, "A.8.")
			case gdpr:
				ok = strings.HasPrefix(r.ID, "Art. ")
			}
			if !ok {
				t.Errorf("%s: unexpected reference %s %s", c.ID, r.Framework, r.ID)
			}
		}
	}
}

func TestOSCALShape(t *testing.T) {
	r := Evaluate(devFacts())
	doc := OSCAL(r)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		AR struct {
			UUID     string `json:"uuid"`
			Metadata struct {
				Title, LastModified, Version, OSCALVersion string
			} `json:"metadata"`
			ImportAP struct {
				Href string `json:"href"`
			} `json:"import-ap"`
			Results []struct {
				UUID, Title, Description, Start string
				ReviewedControls                map[string]any   `json:"reviewed-controls"`
				Observations                    []map[string]any `json:"observations"`
				Findings                        []struct {
					Target struct {
						TargetID string `json:"target-id"`
						Status   struct {
							State string `json:"state"`
						} `json:"status"`
					} `json:"target"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	res := back.AR.Results
	if back.AR.UUID == "" || back.AR.ImportAP.Href == "" || len(res) != 1 || res[0].ReviewedControls == nil ||
		res[0].Start == "" {
		t.Fatalf("missing required fields: %s", raw)
	}
	if len(res[0].Observations) != len(r.Controls) || len(res[0].Findings) != r.Passed+r.Failed {
		t.Fatalf("%d observations, %d findings", len(res[0].Observations), len(res[0].Findings))
	}
	for _, f := range res[0].Findings {
		if s := f.Target.Status.State; s != "satisfied" && s != "not-satisfied" {
			t.Fatalf("finding %s state %q", f.Target.TargetID, s)
		}
	}
	again, _ := json.Marshal(OSCAL(r))
	if string(again) != string(raw) {
		t.Fatal("OSCAL output is not deterministic")
	}
}
