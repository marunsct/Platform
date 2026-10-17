package matura_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	matura "github.com/marunsct/Platform/sdk/go"
	"github.com/marunsct/Platform/sdk/go/maturatest"
)

func TestMiddlewareAndRequire(t *testing.T) {
	iss := newIssuer(t)
	var recorded []string
	mw := matura.Middleware(iss.Verifier(), matura.OnPrincipal(func(r *http.Request, p *matura.Principal) error {
		recorded = append(recorded, p.UserID)
		if p.UserID == "broken" {
			return errors.New("db down")
		}
		return nil
	}))
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := matura.PrincipalFrom(r.Context())
		_, _ = w.Write([]byte(p.TenantID))
	})
	mux := http.NewServeMux()
	mux.Handle("GET /notes", mw(matura.RequirePermission("note.read")(ok)))
	mux.Handle("POST /notes", mw(matura.RequireTenant()(matura.RequirePermission("note.read", "note.write")(ok))))
	mux.Handle("GET /admin", mw(matura.RequireTenantRole("owner", "admin")(ok)))
	mux.Handle("GET /editors", mw(matura.RequireRole("editor")(ok)))
	mux.Handle("GET /bare", matura.RequirePermission("x")(ok))

	reader := mustToken(t, iss, maturatest.TokenOptions{UserID: U1, TenantID: T1, Perms: []string{"note.read"}})
	admin := mustToken(t, iss, maturatest.TokenOptions{UserID: U1, TenantID: T1, TenantRoles: []string{"admin"},
		Roles: []string{"editor"}, Perms: []string{"*"}})
	noTenant := mustToken(t, iss, maturatest.TokenOptions{UserID: U1, Perms: []string{"*"}})
	broken := mustToken(t, iss, maturatest.TokenOptions{UserID: "broken"})
	cases := []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/notes", "", 401},
		{"GET", "/notes", "not-a-token", 401},
		{"GET", "/notes", reader, 200},
		{"POST", "/notes", reader, 403},
		{"POST", "/notes", admin, 200},
		{"POST", "/notes", noTenant, 403},
		{"GET", "/admin", reader, 403},
		{"GET", "/admin", admin, 200},
		{"GET", "/editors", reader, 403},
		{"GET", "/editors", admin, 200},
		{"GET", "/bare", admin, 401},
		{"GET", "/notes", broken, 500},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if c.token != "" {
			r.Header.Set("Authorization", "Bearer "+c.token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s %s: %d %s, want %d", c.method, c.path, w.Code, w.Body, c.want)
		}
		if c.want == 200 && w.Body.String() != T1 {
			t.Errorf("%s %s: body %q", c.method, c.path, w.Body)
		}
		if c.want >= 400 && w.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("%s %s: content type %q", c.method, c.path, w.Header().Get("Content-Type"))
		}
		if c.want == 401 && !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s %s: no WWW-Authenticate", c.method, c.path)
		}
	}
	if len(recorded) == 0 {
		t.Fatal("OnPrincipal not called")
	}
}

func TestWebhookHandler(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	c.On("matura.tenant.deleting", func(ctx context.Context, db matura.Executor, e *matura.Event) error {
		return errors.New("hook failed")
	})
	now := time.Unix(1792140360, 0)
	h := &matura.WebhookHandler{Secrets: [][]byte{[]byte("whsec_old"), []byte("whsec_new")}, Contract: c, DB: pool,
		Now: func() time.Time { return now }}
	var logged []error
	h.OnError = func(r *http.Request, err error) { logged = append(logged, err) }
	event := map[string]any{"specversion": "1.0", "id": "evt_1", "type": "matura.membership.added",
		"data": map[string]any{"object": "membership", "version": 41, "membership": map[string]any{
			"tenant_id": T1, "user_id": U1, "tenant_role": "admin", "status": "active"}}}
	send := func(method string, body []byte, header http.Header) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/matura/events", bytes.NewReader(body))
		for k, v := range header {
			r.Header[k] = v
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	signed := func(secret string, ev any, at time.Time) ([]byte, http.Header) {
		body, hdr, err := maturatest.SignedEvent([]byte(secret), ev, at)
		if err != nil {
			t.Fatal(err)
		}
		return body, hdr
	}

	body, hdr := signed("whsec_new", event, now)
	if hdr.Get("Matura-Event-Id") != "evt_1" {
		t.Fatalf("headers = %v", hdr)
	}
	for i := range 2 { // a retry of the same event is answered 204 and not applied again
		if w := send("POST", body, hdr); w.Code != http.StatusNoContent {
			t.Fatalf("delivery %d: %d %s", i, w.Code, w.Body)
		}
	}
	var role string
	var inbox int
	_ = pool.QueryRow(ctx, `SELECT tenant_role FROM matura_membership`).Scan(&role)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM matura_inbox`).Scan(&inbox)
	if role != "admin" || inbox != 1 {
		t.Fatalf("role = %q, inbox = %d", role, inbox)
	}

	forged := bytes.Replace(body, []byte(`"admin"`), []byte(`"owner"`), 1)
	oldBody, oldHdr := signed("whsec_new", event, now.Add(-6*time.Minute))
	otherBody, otherHdr := signed("whsec_other", event, now)
	notEvent, notEventHdr := signed("whsec_old", []any{1, 2}, now)
	invalid, invalidHdr := signed("whsec_old", map[string]any{"id": "evt_2", "data": map[string]any{
		"object": "membership", "version": 3, "membership": map[string]any{"tenant_id": T1}}}, now)
	failing, failingHdr := signed("whsec_old", map[string]any{"id": "evt_3", "type": "matura.tenant.deleting",
		"data": map[string]any{"object": "tenant", "version": 50, "tenant": map[string]any{"id": T1, "slug": "acme",
			"name": "Acme", "status": "deleting"}}}, now)
	for name, c := range map[string]struct {
		method string
		body   []byte
		hdr    http.Header
		want   int
	}{
		"forged":        {"POST", forged, hdr, 401},
		"too old":       {"POST", oldBody, oldHdr, 401},
		"other secret":  {"POST", otherBody, otherHdr, 401},
		"unsigned":      {"POST", body, http.Header{}, 401},
		"not an event":  {"POST", notEvent, notEventHdr, 400},
		"missing field": {"POST", invalid, invalidHdr, 400},
		"hook fails":    {"POST", failing, failingHdr, 500},
		"GET":           {"GET", nil, nil, 405},
	} {
		w := send(c.method, c.body, c.hdr)
		if w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body, c.want)
		}
		var p map[string]any
		if json.Unmarshal(w.Body.Bytes(), &p) != nil || p["detail"] == nil {
			t.Errorf("%s: body %s", name, w.Body)
		}
	}
	_ = pool.QueryRow(ctx, `SELECT tenant_role FROM matura_membership`).Scan(&role)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM matura_inbox`).Scan(&inbox)
	if role != "admin" || inbox != 1 || len(logged) != 1 {
		t.Fatalf("after refusals: role = %q, inbox = %d, logged = %v", role, inbox, logged)
	}

	// the constructor for one secret, and the body limit
	small := matura.NewWebhookHandler("whsec_new", c, pool)
	small.MaxBytes, small.Now = 10, h.Now
	w := httptest.NewRecorder()
	small.ServeHTTP(w, httptest.NewRequest("POST", "/", bytes.NewReader(body)))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: %d", w.Code)
	}
}
