package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/audit"
	"github.com/marunsct/Platform/internal/events"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
)

// raw sends a request and returns the status, headers and body unparsed.
func (c client) raw(method, path string, header map[string]string) (int, http.Header, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, nil)
	req.Header.Set("X-Matura-Dev-User", c.user.String())
	req.Header.Set("X-Matura-Dev-Email", emailOf(c))
	if c.op {
		req.Header.Set("X-Matura-Dev-Operator", "true")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, body
}

func auditItems(t *testing.T, page map[string]any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, it := range page["items"].([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func actions(items []map[string]any) []string {
	var out []string
	for _, it := range items {
		out = append(out, it["action"].(string))
	}
	return out
}

// superuser connects to the test database as the server's superuser, which bypasses row-level security and
// grants: the tamperer the hash chain exists for.
func superuser(t *testing.T, pool *pgxpool.Pool) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(os.Getenv("MATURA_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = pool.Config().ConnConfig.Database
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func exportChain(t *testing.T, c client, tid string) []store.AuditEvent {
	t.Helper()
	status, h, body := c.raw("GET", "/v1/tenants/"+tid+"/audit/export", nil)
	if status != http.StatusOK || h.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("export: %d %s %s", status, h.Get("Content-Type"), body)
	}
	var out []store.AuditEvent
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e store.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("export line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

// TestAuditLog: every change lands in the tenant's chain with its actor and request, the chain verifies, the export
// carries the same chain, pages walk it without gaps, and only owners and admins read it.
func TestAuditLog(t *testing.T) {
	srv, st, _, pool := setupPool(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user, "tenant_role": "member"})
	inv := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/invitations", map[string]any{"email": "dan@example.test"})
	alice.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+aid+"/invitations/"+inv["id"].(string), nil)
	// HTML characters, non-ASCII text and numbers must hash the same after a round trip through jsonb
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "R&D <Zürich> \"1.50\""})

	// a member may not read the log; the refusal is itself recorded
	bob.must(http.StatusForbidden, "GET", "/v1/tenants/"+aid+"/audit", nil)

	status, h, body := alice.raw("GET", "/v1/tenants/"+aid+"/audit", map[string]string{"X-Request-Id": "req-test-1",
		"User-Agent": "audit-test/1"})
	if status != http.StatusOK || h.Get("X-Request-Id") != "req-test-1" {
		t.Fatalf("list: %d %s", status, body)
	}
	var page map[string]any
	_ = json.Unmarshal(body, &page)
	items := auditItems(t, page)
	got := strings.Join(actions(items), " ")
	for _, want := range []string{"tenant.created", "workspace.created", "membership.added", "invitation.created",
		"invitation.revoked", "authz.denied"} {
		if !strings.Contains(got, want) {
			t.Fatalf("audit log lacks %s: %s", want, got)
		}
	}
	if items[0]["action"] != "authz.denied" { // newest first
		t.Fatalf("order: %s", got)
	}
	denied := items[0]
	if a := denied["actor"].(map[string]any); a["id"] != bob.user.String() || a["kind"] != "user" ||
		denied["data"].(map[string]any)["reason"] != "forbidden" || denied["ip"] != "127.0.0.1" {
		t.Fatalf("denied event: %v", denied)
	}
	for _, it := range items {
		if it["action"] == "invitation.created" {
			a := it["actor"].(map[string]any)
			if a["email"] != emailOf(alice) || it["request_id"] == "" || it["target"] != "tenants/"+aid+"/invitations/"+inv["id"].(string) {
				t.Fatalf("invitation event: %v", it)
			}
		}
	}

	// the export is the chain: contiguous, linked, and every hash recomputes
	chain := exportChain(t, alice, aid)
	if len(chain) != len(items)+1 || chain[len(chain)-1].Action != "audit.exported" { // the export records itself
		t.Fatalf("export has %d events, list %d", len(chain), len(items))
	}
	prev := strings.Repeat("0", 64)
	for i, e := range chain {
		h, err := e.ComputeHash()
		if err != nil || e.Seq != int64(i+1) || e.PrevHash != prev || h != e.Hash {
			t.Fatalf("export event %d: seq %d prev %s hash %s recomputed %s (%v)", i, e.Seq, e.PrevHash, e.Hash, h, err)
		}
		prev = e.Hash
	}
	v := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit:verify", nil)
	if v["ok"] != true || v["events"].(float64) != float64(len(chain)) {
		t.Fatalf("verify: %v", v)
	}

	// pages: many events, walked 7 at a time, give every event once, newest first
	for i := range 20 {
		alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "ws" + strconv.Itoa(i)})
	}
	var walked []float64
	cursor := ""
	for {
		p := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit?limit=7&action=workspace.&cursor="+cursor, nil)
		for _, it := range auditItems(t, p) {
			walked = append(walked, it["id"].(float64))
			if it["action"] != "workspace.created" {
				t.Fatalf("action filter let through %v", it["action"])
			}
		}
		if p["next_cursor"] == nil {
			break
		}
		cursor = p["next_cursor"].(string)
	}
	if len(walked) != 22 { // Default + R&D + 20
		t.Fatalf("walked %d workspace events", len(walked))
	}
	for i := 1; i < len(walked); i++ {
		if walked[i] >= walked[i-1] {
			t.Fatalf("pages not strictly newest first: %v", walked)
		}
	}
	// actor and time filters
	byBob := auditItems(t, alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit?actor="+bob.user.String(), nil))
	if len(byBob) != 1 || byBob[0]["action"] != "authz.denied" {
		t.Fatalf("actor filter: %v", actions(byBob))
	}
	byEmail := auditItems(t, alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit?limit=1000&actor="+strings.ToUpper(emailOf(alice)), nil))
	if len(byEmail) < 25 {
		t.Fatalf("email filter found %d", len(byEmail))
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if n := len(auditItems(t, alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit?from="+future, nil))); n != 0 {
		t.Fatalf("from filter: %d", n)
	}
	alice.must(http.StatusBadRequest, "GET", "/v1/tenants/"+aid+"/audit?from=yesterday", nil)

	// isolation: another tenant's owner, and the store under another tenant's scope, see nothing of acme's
	carol := client{t: t, srv: srv, user: ids.New()}
	globex := carol.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	gid := uuid.MustParse(globex["id"].(string))
	carol.must(http.StatusNotFound, "GET", "/v1/tenants/"+aid+"/audit", nil)
	carol.must(http.StatusNotFound, "GET", "/v1/tenants/"+aid+"/audit/export", nil)
	carol.must(http.StatusNotFound, "GET", "/v1/tenants/"+aid+"/audit:verify", nil)
	acmeID := uuid.MustParse(aid)
	leaked, err := st.ListAudit(ctx, store.Scope{UserID: carol.user}.InTenant(gid), store.AuditQuery{Tenant: &acmeID})
	if err != nil || len(leaked) != 0 {
		t.Fatalf("globex scope read %d acme events (%v)", len(leaked), err)
	}
	all, err := st.ListAudit(ctx, store.Scope{UserID: carol.user}.InTenant(gid), store.AuditQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.TenantID == nil || *e.TenantID != gid {
			t.Fatalf("globex scope read an event of %v: %s", e.TenantID, e.Action)
		}
	}

	// append-only: the runtime role can neither change nor delete events
	for _, q := range []string{`UPDATE audit_event SET action = 'x'`, `DELETE FROM audit_event`, `TRUNCATE audit_event`} {
		if _, err := pool.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s as the runtime role: %v", q, err)
		}
	}

	// operators read every chain; the installation chain holds app and user events
	alice.must(http.StatusForbidden, "GET", "/admin/v1/audit", nil)
	inst := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant=installation&limit=1000", nil))
	instActions := strings.Join(actions(inst), " ")
	if !strings.Contains(instActions, "app.manifest.updated") || !strings.Contains(instActions, "user.created") ||
		!strings.Contains(instActions, "authz.denied") {
		t.Fatalf("installation chain: %s", instActions)
	}
	for _, e := range inst {
		if e["tenant_id"] != nil {
			t.Fatalf("installation filter returned a tenant event: %v", e)
		}
	}
	if op := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant="+aid+"&limit=5", nil)); len(op) != 5 {
		t.Fatalf("operator tenant filter: %d", len(op))
	}
	if v := op.must(http.StatusOK, "GET", "/admin/v1/audit:verify", nil); v["ok"] != true {
		t.Fatalf("installation chain verify: %v", v)
	}
	if v := op.must(http.StatusOK, "GET", "/admin/v1/audit:verify?tenant="+aid, nil); v["ok"] != true {
		t.Fatalf("operator verify of acme: %v", v)
	}
}

// TestAuditTamperDetection: a superuser who edits, removes or truncates events breaks the chain, and verify names
// the first broken position.
func TestAuditTamperDetection(t *testing.T) {
	srv, _, _, pool := setupPool(t)
	ctx := context.Background()
	su := superuser(t, pool)
	alice := client{t: t, srv: srv, user: ids.New()}
	newTenant := func(slug string) string {
		tn := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": slug, "name": slug})
		for i := range 4 {
			alice.must(http.StatusCreated, "POST", "/v1/tenants/"+tn["id"].(string)+"/workspaces",
				map[string]any{"name": "w" + strconv.Itoa(i)})
		}
		return tn["id"].(string)
	}
	verify := func(tid string) map[string]any {
		return alice.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/audit:verify", nil)
	}
	brk := func(v map[string]any) (float64, string) {
		b, _ := v["first_break"].(map[string]any)
		if b == nil {
			t.Fatalf("no break reported: %v", v)
		}
		return b["seq"].(float64), b["reason"].(string)
	}

	// an edited field
	edited := newTenant("edited")
	if v := verify(edited); v["ok"] != true {
		t.Fatalf("clean chain: %v", v)
	}
	if _, err := su.Exec(ctx, `UPDATE audit_event SET data = jsonb_set(data, '{name}', '"Hacked"')
		WHERE tenant_id = $1 AND seq = 4`, edited); err != nil {
		t.Fatal(err)
	}
	v := verify(edited)
	if seq, reason := brk(v); v["ok"] != false || seq != 4 || !strings.Contains(reason, "hash") || v["events"].(float64) != 3 {
		t.Fatalf("edit: %v", v)
	}

	// an edited event with its hash recomputed still breaks the link to the next one
	relinked := newTenant("relinked")
	var e store.AuditEvent
	row := su.QueryRow(ctx, `SELECT seq, time, actor_kind, coalesce(actor_email, ''), action, target,
		coalesce(request_id, ''), coalesce(ip, ''), coalesce(user_agent, ''), data, encode(prev_hash, 'hex'), actor_id
		FROM audit_event WHERE tenant_id = $1 AND seq = 3`, relinked)
	tid := uuid.MustParse(relinked)
	e.TenantID = &tid
	if err := row.Scan(&e.Seq, &e.Time, &e.Actor.Kind, &e.Actor.Email, &e.Action, &e.Target, &e.RequestID, &e.IP,
		&e.UserAgent, &e.Data, &e.PrevHash, &e.Actor.ID); err != nil {
		t.Fatal(err)
	}
	e.Action = "workspace.renamed"
	h, _ := e.ComputeHash()
	if _, err := su.Exec(ctx, `UPDATE audit_event SET action = $2, hash = decode($3, 'hex') WHERE tenant_id = $1 AND seq = 3`,
		relinked, e.Action, h); err != nil {
		t.Fatal(err)
	}
	if seq, reason := brk(verify(relinked)); seq != 4 || !strings.Contains(reason, "prev_hash") {
		t.Fatalf("relinked: %d %s", int(seq), reason)
	}

	// a removed event
	removed := newTenant("removed")
	if _, err := su.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id = $1 AND seq = 2`, removed); err != nil {
		t.Fatal(err)
	}
	if seq, reason := brk(verify(removed)); seq != 2 || !strings.Contains(reason, "missing") {
		t.Fatalf("removed: %d %s", int(seq), reason)
	}

	// a cut-off tail: every remaining event is fine, but the chain no longer reaches its head
	cut := newTenant("cut")
	if _, err := su.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id = $1 AND seq >= 5`, cut); err != nil {
		t.Fatal(err)
	}
	if v := verify(cut); v["ok"] != false || v["events"].(float64) != 4 {
		t.Fatalf("cut: %v", v)
	}

	// other chains are untouched
	clean := newTenant("clean")
	if v := verify(clean); v["ok"] != true {
		t.Fatalf("clean chain after tampering elsewhere: %v", v)
	}
}

// sinkReceiver is a SIEM stand-in: it checks signatures, can be told to fail, and records the events it acknowledged.
type sinkReceiver struct {
	mu     sync.Mutex
	secret []byte
	fail   bool
	got    []store.AuditEvent
	bad    int
	posts  int
}

func (rc *sinkReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.posts++
	body, _ := io.ReadAll(r.Body)
	if err := events.Verify(rc.secret, r.Header.Get("Matura-Signature"), body, time.Now()); err != nil ||
		r.Header.Get("Content-Type") != "application/x-ndjson" {
		rc.bad++
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if rc.fail {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		var e store.AuditEvent
		_ = json.Unmarshal(line, &e)
		rc.got = append(rc.got, e)
	}
	w.WriteHeader(http.StatusAccepted)
}

// TestAuditStreaming: a destination gets the chain in order and complete, signed; after an outage it resumes from
// its cursor without skipping anything.
func TestAuditStreaming(t *testing.T) {
	srv, st, keys := setupFull(t)
	store.AllowHTTPWebhooks = true
	t.Cleanup(func() { store.AllowHTTPWebhooks = false })
	ctx := context.Background()
	alice := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	other := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "other", "name": "Other"})

	rc := &sinkReceiver{}
	sinkSrv := httptest.NewServer(rc)
	t.Cleanup(sinkSrv.Close)
	base := "/v1/tenants/" + aid + "/audit/sinks"
	alice.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"url": "ftp://siem.test"})
	alice.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"url": sinkSrv.URL, "kind": "syslog"})
	sink := alice.must(http.StatusCreated, "POST", base, map[string]any{"url": sinkSrv.URL, "backfill": true})
	rc.secret = []byte(sink["secret"].(string))
	sid := sink["id"].(string)
	if items := alice.must(http.StatusOK, "GET", base, nil)["items"].([]any); len(items) != 1 ||
		items[0].(map[string]any)["secret"] != nil {
		t.Fatalf("list: %v", items)
	}

	streamer := &audit.Streamer{Store: st, Keys: keys, Batch: 3}
	drain := func() {
		for range 20 {
			if err := streamer.Round(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	drain()
	head := func() int64 {
		v := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit:verify", nil)
		return int64(v["head_seq"].(float64))
	}
	check := func() {
		t.Helper()
		if rc.bad != 0 {
			t.Fatalf("%d bad deliveries", rc.bad)
		}
		for i, e := range rc.got {
			if e.Seq != int64(i+1) || e.TenantID == nil || e.TenantID.String() != aid {
				t.Fatalf("delivery %d: seq %d tenant %v", i, e.Seq, e.TenantID)
			}
		}
	}
	check()
	if n := int64(len(rc.got)); n == 0 || n != head() {
		t.Fatalf("delivered %d of %d", n, head())
	}

	// the receiver goes down: nothing is acknowledged, the cursor stays, the destination shows failing
	rc.fail = true
	for i := range 5 {
		alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "w" + strconv.Itoa(i)})
	}
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+other["id"].(string)+"/workspaces", map[string]any{"name": "x"})
	before := len(rc.got)
	drain()
	s := alice.must(http.StatusOK, "GET", base, nil)["items"].([]any)[0].(map[string]any)
	if len(rc.got) != before || s["status"] != "failing" || s["last_status"].(float64) != 502 ||
		int(s["cursor"].(float64)) != before {
		t.Fatalf("while down: %v", s)
	}
	// back up; re-activating retries at once and the backlog arrives complete and in order
	rc.fail = false
	alice.must(http.StatusOK, "PATCH", base+"/"+sid, map[string]any{"status": "active"})
	drain()
	check()
	if n := int64(len(rc.got)); n != head() {
		t.Fatalf("after recovery delivered %d of %d", n, head())
	}
	s = alice.must(http.StatusOK, "GET", base, nil)["items"].([]any)[0].(map[string]any)
	if s["status"] != "active" || int64(s["cursor"].(float64)) != head() {
		t.Fatalf("after recovery: %v", s)
	}

	// disabled destinations get nothing; deleting is recorded
	alice.must(http.StatusOK, "PATCH", base+"/"+sid, map[string]any{"status": "disabled"})
	posts := rc.posts
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "late"})
	drain()
	if rc.posts != posts {
		t.Fatal("a disabled destination was called")
	}
	alice.must(http.StatusNoContent, "DELETE", base+"/"+sid, nil)
	alice.must(http.StatusNotFound, "DELETE", base+"/"+sid, nil)
	last := auditItems(t, alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit?limit=1", nil))[0]
	if last["action"] != "audit.sink.deleted" {
		t.Fatalf("last event: %v", last["action"])
	}
}

// TestSecurityPolicy: invitations keep to the allowed domains, the IP allow-list refuses other addresses (not
// operators), and an admin cannot lock themselves out.
func TestSecurityPolicy(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user, "tenant_role": "member"})
	base := "/v1/tenants/" + aid + "/security-policy"

	p := alice.must(http.StatusOK, "GET", base, nil)
	if p["version"].(float64) != 0 || p["require_mfa"] != false || len(p["ip_allowlist"].([]any)) != 0 {
		t.Fatalf("default policy: %v", p)
	}
	bob.must(http.StatusForbidden, "GET", base, nil)
	bob.must(http.StatusForbidden, "PUT", base, map[string]any{"require_mfa": true})

	// validation
	for _, bad := range []map[string]any{
		{"session_max_age": 10},
		{"session_max_age": 3600, "idle_timeout": 7200},
		{"allowed_email_domains": []string{"not a domain"}},
		{"ip_allowlist": []string{"10.0.0.0/33"}},
		{"ip_allowlist": []string{"10.0.0.0/8"}}, // would lock alice (127.0.0.1) out
	} {
		alice.must(http.StatusUnprocessableEntity, "PUT", base, bad)
	}

	p = alice.must(http.StatusOK, "PUT", base, map[string]any{"require_mfa": true, "session_max_age": 28800,
		"idle_timeout": 1800, "allowed_email_domains": []string{"Example.TEST", "@example.test"},
		"ip_allowlist": []string{"127.0.0.1", "10.1.2.3/8"}})
	if d := p["allowed_email_domains"].([]any); len(d) != 1 || d[0] != "example.test" {
		t.Fatalf("domains: %v", d)
	}
	if n := p["ip_allowlist"].([]any); len(n) != 2 || n[0] != "127.0.0.1/32" || n[1] != "10.0.0.0/8" {
		t.Fatalf("allow-list: %v", n)
	}
	ver := p["version"].(float64)

	// stale If-Match
	req, _ := http.NewRequest("PUT", srv.URL+base, strings.NewReader(`{"require_mfa":false,"ip_allowlist":["127.0.0.1"]}`))
	req.Header.Set("X-Matura-Dev-User", alice.user.String())
	req.Header.Set("If-Match", `"1"`)
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: %v %v", res.StatusCode, err)
	}

	// invitations keep to the allowed domains, subdomains included
	inv := "/v1/tenants/" + aid + "/invitations"
	alice.must(http.StatusUnprocessableEntity, "POST", inv, map[string]any{"email": "eve@evil.test"})
	alice.must(http.StatusUnprocessableEntity, "POST", inv, map[string]any{"email": "eve@notexample.test"})
	alice.must(http.StatusCreated, "POST", inv, map[string]any{"email": "dan@example.test"})
	alice.must(http.StatusCreated, "POST", inv, map[string]any{"email": "erin@eu.example.test"})

	// an allow-list without the caller's address: members are refused, operators are not, non-members still get 404
	p = op.must(http.StatusOK, "PUT", base, map[string]any{"ip_allowlist": []string{"10.0.0.0/8"}})
	if p["version"].(float64) <= ver || p["require_mfa"] != false {
		t.Fatalf("operator put: %v", p)
	}
	status, _, body := alice.raw("GET", "/v1/tenants/"+aid, nil)
	if status != http.StatusForbidden || !strings.Contains(string(body), "ip-not-allowed") {
		t.Fatalf("outside the allow-list: %d %s", status, body)
	}
	bob.must(http.StatusForbidden, "GET", "/v1/tenants/"+aid+"/members", nil)
	op.must(http.StatusOK, "GET", "/v1/tenants/"+aid, nil)
	stranger := client{t: t, srv: srv, user: ids.New()}
	stranger.must(http.StatusNotFound, "GET", "/v1/tenants/"+aid, nil)
	// other tenants are unaffected
	alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "beta", "name": "Beta"})

	log := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant="+aid+"&action=authz.denied", nil))
	if len(log) != 4 || log[0]["data"].(map[string]any)["reason"] != "ip-not-allowed" ||
		log[1]["data"].(map[string]any)["reason"] != "ip-not-allowed" { // and bob's two earlier refusals
		t.Fatalf("refusals in the audit log: %v", log)
	}
	changes := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant="+aid+"&action=security_policy.", nil))
	if len(changes) != 2 || changes[0]["actor"].(map[string]any)["kind"] != "operator" {
		t.Fatalf("policy changes in the audit log: %v", changes)
	}

	// lifting the list lets members back in at once on this replica
	op.must(http.StatusOK, "PUT", base, map[string]any{})
	alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid, nil)
}
