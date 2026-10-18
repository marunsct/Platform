package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/readiness"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func intp(i int) *int { return &i }

// fixedReport is a report from a known installation: production settings, one company with every gap closed but
// streaming, one without a policy, a restore test eight days old and no access review.
func fixedReport() readiness.Report {
	now := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	f := readiness.Facts{Now: now,
		Install: readiness.Install{Product: "Acme Cloud", Env: "production", Auth: "oidc", KEKConfigured: true, TenantKeys: true,
			SMTPConfigured: true, MetricsEnabled: true, PublicURL: "https://id.acme.example"},
		Installation: readiness.Chain{OK: true, Events: 212},
		Webhooks:     readiness.Webhooks{Active: 2, Failing: 1, Dropped: 3},
		Tenants: []readiness.Tenant{
			{ID: uuid.MustParse("0192a000-0000-7000-8000-000000000001"), Slug: "acme", Kind: "company", Status: "active",
				PolicySet: true, RequireMFA: true, SessionMaxAge: intp(28800), IdleTimeout: intp(1800),
				AllowedEmailDomains: 1, IPAllowlist: 1, Audit: readiness.Chain{OK: true, Events: 90}},
			{ID: uuid.MustParse("0192a000-0000-7000-8000-000000000002"), Slug: "globex", Kind: "company", Status: "active",
				SinksActive: 1, Audit: readiness.Chain{OK: true, Events: 14}},
		},
		Latest: map[string]*readiness.Evidence{
			"restore-test":       {Kind: "restore-test", Passed: true, RecordedAt: now.Add(-8 * 24 * time.Hour)},
			"vulnerability-scan": {Kind: "vulnerability-scan", Passed: true, RecordedAt: now.Add(-2 * 24 * time.Hour)},
		},
		Recent: map[string]int{"restore-test": 2, "vulnerability-scan": 1},
	}
	return readiness.Evaluate(f)
}

// fakeMaturad serves the fixed report to an operator token, like GET /admin/v1/readiness.
func fakeMaturad(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/readiness" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer op-token" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"missing bearer token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fixedReport())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./cmd/matura -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file (go test ./cmd/matura -update after checking the change):\n%s", name, got)
	}
}

func runCheck(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"check"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCheckOutputs(t *testing.T) {
	srv := fakeMaturad(t)
	t.Setenv("MATURA_TOKEN", "op-token")
	t.Setenv("MATURA_URL", srv.URL)

	code, out, stderr := runCheck(t, "--json")
	if code != 0 {
		t.Fatalf("--json: exit %d: %s", code, stderr)
	}
	golden(t, "check.json", []byte(out))
	var rep readiness.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Score != 63.2 || rep.Failed != 7 {
		t.Fatalf("report: score %v, %d failed, %v", rep.Score, rep.Failed, err)
	}

	code, out, _ = runCheck(t, "--oscal")
	if code != 0 {
		t.Fatalf("--oscal: exit %d", code)
	}
	golden(t, "check.oscal.json", []byte(out))

	code, out, _ = runCheck(t)
	if code != 0 {
		t.Fatalf("table: exit %d", code)
	}
	golden(t, "check.txt", []byte(out))
	for _, want := range []string{"FAIL    install-webhooks", "fix:  Review operators", "maps to: SOC 2 CC6.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q", want)
		}
	}
}

func TestCheckMinScoreAndErrors(t *testing.T) {
	srv := fakeMaturad(t)
	t.Setenv("MATURA_URL", srv.URL)
	t.Setenv("MATURA_TOKEN", "op-token")
	if code, _, _ := runCheck(t, "--json", "--min-score", "60"); code != 0 {
		t.Fatalf("score above the minimum: exit %d", code)
	}
	if code, _, stderr := runCheck(t, "--json", "--min-score", "70"); code != 1 || !strings.Contains(stderr, "below --min-score") {
		t.Fatalf("score below the minimum: exit %d, %q", code, stderr)
	}
	if code, _, _ := runCheck(t, "--json", "--oscal"); code != 2 {
		t.Fatalf("--json with --oscal: exit %d", code)
	}
	t.Setenv("MATURA_TOKEN", "")
	if code, _, stderr := runCheck(t); code != 2 || !strings.Contains(stderr, "set MATURA_TOKEN") {
		t.Fatalf("no token: exit %d, %q", code, stderr)
	}
	if code := run([]string{"nope"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("unknown command: exit %d", code)
	}
}

func TestCheckFillsPolicies(t *testing.T) {
	srv := fakeMaturad(t)
	t.Setenv("MATURA_URL", srv.URL)
	t.Setenv("MATURA_TOKEN", "op-token")
	out := t.TempDir()
	code, stdout, stderr := runCheck(t, "--json", "--policies", "../../docs/templates", "--out", out,
		"--set", "organisation=Acme Ltd", "--set", "backup_frequency=daily at 02:00 UTC")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !json.Valid([]byte(stdout)) {
		t.Fatal("--json output mixed with policy messages")
	}
	for _, name := range []string{"access-control-policy.md", "incident-response-policy.md", "backup-policy.md"} {
		if !strings.Contains(stderr, filepath.Join(out, name)) {
			t.Errorf("no message for %s: %s", name, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "README.md")); err == nil {
		t.Error("README.md was treated as a template")
	}
	access, _ := os.ReadFile(filepath.Join(out, "access-control-policy.md"))
	backup, _ := os.ReadFile(filepath.Join(out, "backup-policy.md"))
	for doc, wants := range map[string][]string{
		string(access): {"# Access control policy — Acme Ltd", "**TEMPLATE.**",
			"required by the security policy of 1 of 2 organisations", "OpenID Connect", "{{policy_owner}}",
			"3 of 3 chains verified on 2026-10-17", "was on none recorded"},
		string(backup): {"Backups run daily at 02:00 UTC", "Last recorded: 2026-10-09\n  (passed); 2 in the 90 days"},
	} {
		for _, w := range wants {
			if !strings.Contains(doc, w) {
				t.Errorf("filled policy lacks %q", w)
			}
		}
	}
	if !strings.Contains(stderr, "still to fill") || !strings.Contains(stderr, "policy_owner") ||
		strings.Contains(stderr, "organisation,") {
		t.Errorf("unfilled placeholders not reported correctly: %s", stderr)
	}
}

// TestCheckAgainstMaturad runs the command against a real maturad over a test database.
func TestCheckAgainstMaturad(t *testing.T) {
	pool := testdb.New(t)
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	server := api.New(store.New(pool), api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetReadiness(readiness.Install{Product: "Matura", Env: "development", Auth: "dev", PublicURL: "http://localhost:8080"})
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	t.Setenv("MATURA_URL", srv.URL)
	t.Setenv("MATURA_TOKEN", "")
	t.Setenv("MATURA_DEV_USER", uuid.NewString())

	code, out, stderr := runCheck(t, "--json", "--min-score", "50")
	var rep readiness.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output: %v: %s %s", err, out, stderr)
	}
	if code != 1 || rep.Score >= 50 || len(rep.Controls) != len(readiness.Catalogue) {
		t.Fatalf("a development install: exit %d, score %v, %d controls", code, rep.Score, len(rep.Controls))
	}
}
