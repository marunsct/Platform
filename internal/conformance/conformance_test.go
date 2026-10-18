package conformance

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/events"
)

// leaks switches deliberate contract violations on in the sample app.
type leaks struct {
	listIgnoresTenant bool
	noPermissionCheck bool
	anyAudience       bool
	anyIssuer         bool
	acceptBadWebhooks bool
	readIgnoresTenant bool
}

type note struct {
	ID, TenantID, Title string
}

// notesApp is a small third-party app written only against the contract: it reads the issuer's JWKS over HTTP,
// verifies iss, aud and exp, checks perms, keeps notes per tid and verifies webhook signatures.
type notesApp struct {
	issuer, audience string
	secret           []byte
	leak             leaks

	mu     sync.Mutex
	notes  []note
	inbox  map[string]bool
	jwks   map[string]*rsa.PublicKey
	events []string // types applied
}

type appClaims struct {
	jwt.RegisteredClaims
	TenantID string   `json:"tid"`
	Perms    []string `json:"perms"`
}

func (a *notesApp) keyfunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	a.mu.Lock()
	k := a.jwks[kid]
	a.mu.Unlock()
	if k != nil {
		return k, nil
	}
	resp, err := http.Get(a.issuer + "/protocol/openid-connect/certs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, jk := range set.Keys {
		n, err1 := base64.RawURLEncoding.DecodeString(jk.N)
		e, err2 := base64.RawURLEncoding.DecodeString(jk.E)
		if err1 != nil || err2 != nil {
			continue
		}
		a.jwks[jk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if k := a.jwks[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown kid")
}

func (a *notesApp) auth(w http.ResponseWriter, r *http.Request, perm string) (*appClaims, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithLeeway(30 * time.Second)}
	if !a.leak.anyIssuer {
		opts = append(opts, jwt.WithIssuer(a.issuer))
	}
	if !a.leak.anyAudience {
		opts = append(opts, jwt.WithAudience(a.audience))
	}
	var c appClaims
	if _, err := jwt.ParseWithClaims(raw, &c, a.keyfunc, opts...); err != nil || c.TenantID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	if !a.leak.noPermissionCheck && !slices.Contains(c.Perms, perm) && !slices.Contains(c.Perms, "*") {
		w.WriteHeader(http.StatusForbidden)
		return nil, false
	}
	return &c, true
}

func (a *notesApp) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /api/notes", func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.auth(w, r, "note.write")
		if !ok {
			return
		}
		var in struct{ Title string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := note{ID: uuid.NewString(), TenantID: c.TenantID, Title: in.Title}
		a.mu.Lock()
		a.notes = append(a.notes, n)
		a.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": n.ID, "title": n.Title}})
	})
	mux.HandleFunc("GET /api/notes", func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.auth(w, r, "note.read")
		if !ok {
			return
		}
		a.mu.Lock()
		out := []note{}
		for _, n := range a.notes {
			if a.leak.listIgnoresTenant || n.TenantID == c.TenantID {
				out = append(out, n)
			}
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /api/notes/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.auth(w, r, "note.read")
		if !ok {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, n := range a.notes {
			if n.ID == r.PathValue("id") && (a.leak.readIgnoresTenant || n.TenantID == c.TenantID) {
				_ = json.NewEncoder(w).Encode(n)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /matura/events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !a.leak.acceptBadWebhooks && !verify(a.secret, r.Header.Get("Matura-Signature"), body, time.Now()) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var ev struct{ ID, Type string }
		if json.Unmarshal(body, &ev) != nil || ev.ID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if !a.inbox[ev.ID] {
			a.inbox[ev.ID] = true
			a.events = append(a.events, ev.Type)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// verify follows contract §10.2.
func verify(secret []byte, header string, body []byte, now time.Time) bool {
	var t, v1 string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			t = v
		case "v1":
			v1 = v
		}
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil || now.Sub(time.Unix(ts, 0)).Abs() > 300*time.Second {
		return false
	}
	got, err := hex.DecodeString(v1)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(t + "." + string(body)))
	return hmac.Equal(got, m.Sum(nil))
}

const notesManifest = `{
  "slug": "notes",
  "permissions": [{"name": "note.read"}, {"name": "note.write"}],
  "roles": [{"name": "editor", "permissions": ["note.read", "note.write"]}],
  "default_role": "editor",
  "conformance": {
    "webhook_path": "/matura/events",
    "resources": [{
      "name": "notes",
      "create": {"method": "POST", "path": "/api/notes", "body": {"title": "conformance {{marker}}"}, "permission": "note.write"},
      "list":   {"method": "GET",  "path": "/api/notes", "permission": "note.read"},
      "read":   {"method": "GET",  "path": "/api/notes/{id}", "permission": "note.read"}
    }]
  }
}`

func runAgainst(t *testing.T, leak leaks, manifest string) (Report, *notesApp) {
	t.Helper()
	iss, err := StartIssuer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = iss.Close() })
	m, err := ParseManifest([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	secret := GenerateSecret()
	app := &notesApp{issuer: iss.URL(), audience: m.Audience(), secret: []byte(secret), leak: leak,
		inbox: map[string]bool{}, jwks: map[string]*rsa.PublicKey{}}
	srv := httptest.NewServer(app.routes())
	t.Cleanup(srv.Close)
	ctx := context.Background()
	if err := WaitForApp(ctx, srv.URL, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{App: srv.URL, Manifest: m, Issuer: iss, WebhookSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	return c.Run(ctx), app
}

func TestHonestAppPasses(t *testing.T) {
	rep, app := runAgainst(t, leaks{}, notesManifest)
	if !rep.OK || rep.Skipped != 0 {
		var sb strings.Builder
		rep.WriteText(&sb)
		t.Fatalf("honest app should pass every check:\n%s", sb.String())
	}
	if rep.Passed != 21 {
		t.Errorf("passed = %d, want 21", rep.Passed)
	}
	// 2 tenants × 5 seed events + valid event; the duplicate and the refused ones are not applied.
	if len(app.events) != 11 {
		t.Errorf("applied %d events, want 11: %v", len(app.events), app.events)
	}
	if !slices.Contains(app.events, "matura.grant.added") || !slices.Contains(app.events, "matura.tenant.created") {
		t.Errorf("seed events missing: %v", app.events)
	}
}

func TestLeakyAppsFailTheirChecks(t *testing.T) {
	cases := []struct {
		name string
		leak leaks
		want []string
	}{
		{"list ignores tenant", leaks{listIgnoresTenant: true}, []string{"isolation/notes/list-other"}},
		{"no permission check", leaks{noPermissionCheck: true}, []string{"perm/notes/create", "perm/notes/list"}},
		{"any audience", leaks{anyAudience: true}, []string{"auth/notes/wrong-audience"}},
		{"any issuer", leaks{anyIssuer: true}, []string{"auth/notes/other-issuer"}},
		{"accepts bad webhooks", leaks{acceptBadWebhooks: true},
			[]string{"events/changed-body", "events/stale-timestamp", "events/other-secret", "events/unsigned"}},
		{"read ignores tenant", leaks{readIgnoresTenant: true}, []string{"isolation/notes/read-other"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, _ := runAgainst(t, tc.leak, notesManifest)
			if rep.OK {
				t.Fatal("report is OK for a leaky app")
			}
			if got := rep.Failures(); !slices.Equal(got, tc.want) {
				var sb strings.Builder
				rep.WriteText(&sb)
				t.Fatalf("failures = %v, want %v\n%s", got, tc.want, sb.String())
			}
		})
	}
}

func TestUnreachableAppFailsWithoutPanicking(t *testing.T) {
	iss, err := StartIssuer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer iss.Close()
	m, err := ParseManifest([]byte(notesManifest))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, err := New(Config{App: url, Manifest: m, Issuer: iss, WebhookSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	rep := c.Run(context.Background())
	if rep.OK || rep.Passed != 0 {
		t.Fatalf("unreachable app: ok=%v passed=%d", rep.OK, rep.Passed)
	}
	if err := WaitForApp(context.Background(), url, 600*time.Millisecond); err == nil {
		t.Fatal("WaitForApp succeeded against a closed server")
	}
}

func TestNoWebhookPathSkipsEventChecks(t *testing.T) {
	manifest := strings.Replace(notesManifest, `"webhook_path": "/matura/events",`, "", 1)
	rep, app := runAgainst(t, leaks{acceptBadWebhooks: true}, manifest)
	if !rep.OK || rep.Skipped != 2 || len(app.events) != 0 {
		t.Fatalf("ok=%v skipped=%d events=%d", rep.OK, rep.Skipped, len(app.events))
	}
}

func TestReportJSON(t *testing.T) {
	rep, _ := runAgainst(t, leaks{readIgnoresTenant: true}, notesManifest)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		OK     bool `json:"ok"`
		Failed int  `json:"failed"`
		Checks []struct {
			ID, Group, Status, Reason string
		} `json:"checks"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.OK || back.Failed != 1 || len(back.Checks) != 21 {
		t.Fatalf("report JSON: %s", b)
	}
	for _, c := range back.Checks {
		if c.ID == "" || c.Group == "" || c.Reason == "" || strings.Contains(c.Reason, "\n") {
			t.Errorf("bad check %+v", c)
		}
	}
}

func TestTokenClaims(t *testing.T) {
	iss, err := StartIssuer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer iss.Close()
	m, _ := ParseManifest([]byte(notesManifest))
	c, err := New(Config{App: "http://127.0.0.1:1", Manifest: m, Issuer: iss, WebhookSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	// The discovery document and JWKS are served where an OIDC library looks for them.
	resp, err := http.Get(iss.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc["issuer"] != iss.URL() || disc["jwks_uri"] != iss.JWKSURL() {
		t.Fatalf("discovery: %v", disc)
	}
	app := &notesApp{issuer: iss.URL(), jwks: map[string]*rsa.PublicKey{}}
	var claims jwt.MapClaims
	if _, err := jwt.ParseWithClaims(c.token(c.a, c.perms), &claims, app.keyfunc,
		jwt.WithIssuer(iss.URL()), jwt.WithAudience("notes")); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"iss", "aud", "azp", "sub", "iat", "exp", "email", "email_verified", "name", "tid",
		"tenant", "wid", "troles", "roles", "perms", "ver", "pmode"} {
		if _, ok := claims[k]; !ok {
			t.Errorf("claim %s missing", k)
		}
	}
	if fmt.Sprint(claims["perms"]) != "[note.read note.write]" || fmt.Sprint(claims["roles"]) != "[editor]" {
		t.Errorf("perms %v roles %v", claims["perms"], claims["roles"])
	}
	if _, err := uuid.Parse(claims["sub"].(string)); err != nil {
		t.Errorf("sub is not a uuid: %v", claims["sub"])
	}
	if _, err := jwt.Parse(mustSign(t, iss.SignUnknown, c.claims(c.a, nil)), app.keyfunc); err == nil {
		t.Error("a token signed by the unknown key verified")
	}
}

func mustSign(t *testing.T, f func(jwt.MapClaims) (string, error), c jwt.MapClaims) string {
	t.Helper()
	s, err := f(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignMatchesMaturad(t *testing.T) {
	body := []byte(`{"id":"evt_1"}`)
	at := time.Unix(1792140300, 0)
	if got, want := Sign("whsec_x", at, body), events.Sign([]byte("whsec_x"), at, body); got != want {
		t.Fatalf("Sign = %s, maturad signs %s", got, want)
	}
	if err := events.Verify([]byte("whsec_x"), Sign("whsec_x", at, body), body, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestManifest(t *testing.T) {
	dir := t.TempDir()
	yml := filepath.Join(dir, "matura.yaml")
	if err := os.WriteFile(yml, []byte(`slug: notes
client_id: notes-web
conformance:
  resources:
    - name: notes
      create: {path: /api/notes, body: {title: "x {{marker}}"}, permission: note.write}
      list: {path: /api/notes, permission: note.read}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(yml)
	if err != nil {
		t.Fatal(err)
	}
	r := m.Conformance.Resources[0]
	if m.Audience() != "notes-web" || r.Create.Method != "POST" || r.List.Method != "GET" || r.Read != nil ||
		!strings.Contains(string(r.Create.Body), "{{marker}}") {
		t.Fatalf("manifest: %+v", m)
	}
	for _, bad := range []string{
		`{}`,
		`{"slug":"x"}`,
		`{"slug":"x","conformance":{"resources":[{"create":{"path":"/a"},"list":{"path":""}}]}}`,
		`{"slug":"x","conformance":{"resources":[{"create":{"path":"/a"},"list":{"path":"/a"},"read":{"path":"/a/1"}}]}}`,
		`{"slug":"x","conformance":{"webhook_path":"events","resources":[{"create":{"path":"/a"},"list":{"path":"/a"}}]}}`,
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Errorf("ParseManifest(%s) succeeded", bad)
		}
	}
}

func TestRecordID(t *testing.T) {
	for body, want := range map[string]string{
		`{"id":"abc"}`: "abc", `{"id":42}`: "42", `{"data":{"id":"d1"}}`: "d1", `{"id":null,"data":{"id":7}}`: "7",
	} {
		if got, err := recordID([]byte(body)); err != nil || got != want {
			t.Errorf("recordID(%s) = %q, %v; want %q", body, got, err, want)
		}
	}
	for _, body := range []string{``, `[]`, `{}`, `{"id":""}`} {
		if _, err := recordID([]byte(body)); err == nil {
			t.Errorf("recordID(%s) succeeded", body)
		}
	}
}
