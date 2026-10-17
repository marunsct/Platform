package api_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/readiness"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

var (
	devInstall  = readiness.Install{Product: "Matura", Env: "development", Auth: "dev", PublicURL: "http://localhost:8080"}
	prodInstall = readiness.Install{Product: "Acme Cloud", Env: "production", Auth: "oidc", KEKConfigured: true,
		SMTPConfigured: true, MetricsEnabled: true, PublicURL: "https://id.acme.example", TrustPage: true,
		SecurityContact: "security@acme.example"}
)

// setupInstall serves the API with a given installation configuration (the authenticator stays the dev one, so
// the tests can act as anyone).
func setupInstall(t *testing.T, in readiness.Install) *httptest.Server {
	pool := testdb.New(t)
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	server := api.New(store.New(pool), api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetReadiness(in)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func statuses(t *testing.T, rep map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range rep["controls"].([]any) {
		m := c.(map[string]any)
		out[m["id"].(string)] = m["status"].(string)
	}
	return out
}

// TestReadinessDevVersusProduction evaluates the same database state under a development and a production
// configuration, then closes the tenant gaps and records evidence, and watches the score rise.
func TestReadinessDevVersusProduction(t *testing.T) {
	store.AllowHTTPWebhooks = true
	t.Cleanup(func() { store.AllowHTTPWebhooks = false })
	for _, tc := range []struct {
		name    string
		in      readiness.Install
		install map[string]string
	}{
		{"development", devInstall, map[string]string{"install-kek": "fail", "install-oidc": "fail",
			"install-production": "fail", "install-tls": "fail", "install-smtp": "fail", "install-metrics": "fail"}},
		{"production", prodInstall, map[string]string{"install-kek": "pass", "install-oidc": "pass",
			"install-production": "pass", "install-tls": "pass", "install-smtp": "pass", "install-metrics": "pass"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := setupInstall(t, tc.in)
			op := client{t: t, srv: srv, user: ids.New(), op: true}
			owner := client{t: t, srv: srv, user: ids.New()}
			owner.must(http.StatusForbidden, "GET", "/admin/v1/readiness", nil)

			acme := owner.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
			aid := acme["id"].(string)
			rep := op.must(http.StatusOK, "GET", "/admin/v1/readiness", nil)
			got := statuses(t, rep)
			for id, want := range tc.install {
				if got[id] != want {
					t.Errorf("%s: %s, want %s", id, got[id], want)
				}
			}
			for id, want := range map[string]string{"install-audit-chain": "pass", "tenant-audit-chain": "pass",
				"install-webhooks": "not-applicable", "tenant-mfa": "fail", "tenant-security-policy": "fail",
				"tenant-invite-domains": "fail", "tenant-audit-streaming": "fail", "tenant-ip-allowlist": "not-applicable",
				"install-restore-test": "fail"} {
				if got[id] != want {
					t.Errorf("%s: %s, want %s", id, got[id], want)
				}
			}
			before := rep["score"].(float64)

			owner.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/security-policy", map[string]any{
				"require_mfa": true, "session_max_age": 28800, "idle_timeout": 1800,
				"allowed_email_domains": []string{"acme.example"}})
			owner.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/audit/sinks", map[string]any{"url": "http://siem.test/in"})
			for _, kind := range []string{"restore-test", "access-review", "vulnerability-scan"} {
				op.must(http.StatusCreated, "POST", "/admin/v1/evidence", map[string]any{"kind": kind, "passed": true,
					"details": map[string]any{"by": "test"}})
			}
			rep = op.must(http.StatusOK, "GET", "/admin/v1/readiness", nil)
			got = statuses(t, rep)
			for _, id := range []string{"tenant-mfa", "tenant-security-policy", "tenant-session-limits",
				"tenant-invite-domains", "tenant-audit-streaming", "install-restore-test", "install-access-review",
				"install-vulnerability-scan", "install-audit-chain", "tenant-audit-chain"} {
				if got[id] != "pass" {
					t.Errorf("after fixes %s: %s", id, got[id])
				}
			}
			after := rep["score"].(float64)
			if after <= before {
				t.Fatalf("score %v did not rise from %v", after, before)
			}
			if tc.name == "production" && after != 100 {
				t.Fatalf("production with every gap closed scores %v: %v", after, got)
			}
			sum := rep["summary"].(map[string]any)
			if sum["tenants"].(float64) != 1 || sum["tenants_mfa"].(float64) != 1 || sum["restore_tests_90d"].(float64) != 1 {
				t.Fatalf("summary %v", sum)
			}
		})
	}
}

func TestEvidence(t *testing.T) {
	srv := setupInstall(t, prodInstall)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	user := client{t: t, srv: srv, user: ids.New()}
	user.must(http.StatusForbidden, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test", "passed": true})
	op.must(http.StatusUnprocessableEntity, "POST", "/admin/v1/evidence", map[string]any{"kind": "pen-test", "passed": true})
	op.must(http.StatusUnprocessableEntity, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test"})
	op.must(http.StatusUnprocessableEntity, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test",
		"passed": true, "details": []string{"not", "an", "object"}})
	op.must(http.StatusBadRequest, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test", "passed": true, "extra": 1})

	failed := op.must(http.StatusCreated, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test",
		"passed": false, "details": map[string]any{"databases": map[string]any{"matura": "row counts differ after restore"}}})
	if failed["passed"] != false || failed["hash"] == "" || failed["seq"].(float64) < 1 ||
		failed["details"].(map[string]any)["databases"] == nil {
		t.Fatalf("recorded: %v", failed)
	}
	if got := statuses(t, op.must(http.StatusOK, "GET", "/admin/v1/readiness", nil))["install-restore-test"]; got != "fail" {
		t.Fatalf("a failed restore test reads %s", got)
	}
	op.must(http.StatusCreated, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test", "passed": true})
	op.must(http.StatusCreated, "POST", "/admin/v1/evidence", map[string]any{"kind": "access-review", "passed": true})
	if got := statuses(t, op.must(http.StatusOK, "GET", "/admin/v1/readiness", nil))["install-restore-test"]; got != "pass" {
		t.Fatalf("a passed restore test reads %s", got)
	}

	items := op.must(http.StatusOK, "GET", "/admin/v1/evidence?kind=restore-test", nil)["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["passed"] != true || items[1].(map[string]any)["passed"] != false {
		t.Fatalf("list newest first: %v", items)
	}
	if all := op.must(http.StatusOK, "GET", "/admin/v1/evidence", nil)["items"].([]any); len(all) != 3 {
		t.Fatalf("all kinds: %d", len(all))
	}
	op.must(http.StatusBadRequest, "GET", "/admin/v1/evidence?kind=nope", nil)

	// evidence lives in the installation audit chain, which still verifies
	ev := op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant=installation&action=evidence.", nil)["items"].([]any)
	if len(ev) != 3 {
		t.Fatalf("audit events: %d", len(ev))
	}
	if v := op.must(http.StatusOK, "GET", "/admin/v1/audit:verify", nil); v["ok"] != true {
		t.Fatalf("verify: %v", v)
	}
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestTrustPage(t *testing.T) {
	off := setupInstall(t, devInstall)
	if res, _ := get(t, off.URL+"/trust"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("trust page off: %d", res.StatusCode)
	}
	if res, _ := get(t, off.URL+"/trust.json"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("trust.json off: %d", res.StatusCode)
	}

	srv := setupInstall(t, prodInstall)
	owner := client{t: t, srv: srv, user: ids.New()}
	owner.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "secretcorp", "name": "Secret Corp"})

	res, page := get(t, srv.URL+"/trust")
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("trust page: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	csp := res.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'none'", "frame-ancestors 'none'", "style-src 'sha256-"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows inline: %q", csp)
	}
	style := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(page)
	if style == nil {
		t.Fatal("no inline style")
	}
	sum := sha256.Sum256([]byte(style[1]))
	if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Fatal("the CSP hash does not match the inline style")
	}
	if res.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("Cache-Control %q", res.Header.Get("Cache-Control"))
	}
	for _, want := range []string{"Acme Cloud security", "Stored secrets are encrypted under an operator-held key",
		"In place", "Not in place", "ISO/IEC 27001:2022 A.8.24", "mailto:security@acme.example",
		"does not certify compliance"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, leak := range []string{"<script", "secretcorp", "Secret Corp", "Outgoing email", "install-smtp",
		"Webhook deliveries", "MATURA_"} {
		if strings.Contains(page, leak) {
			t.Errorf("page shows %q", leak)
		}
	}

	res, doc := get(t, srv.URL+"/trust.json")
	if res.StatusCode != http.StatusOK || !strings.Contains(doc, `"product": "Acme Cloud"`) ||
		strings.Contains(doc, "secretcorp") || strings.Contains(doc, `"evidence"`) {
		t.Fatalf("trust.json: %d %s", res.StatusCode, doc)
	}

	// cached for five minutes, but recording evidence renders it again
	_, again := get(t, srv.URL+"/trust.json")
	if again != doc {
		t.Fatal("trust.json rendered again within five minutes")
	}
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusCreated, "POST", "/admin/v1/evidence", map[string]any{"kind": "restore-test", "passed": true})
	if _, fresh := get(t, srv.URL+"/trust.json"); fresh == doc {
		t.Fatal("new evidence did not refresh the trust page")
	}
}
