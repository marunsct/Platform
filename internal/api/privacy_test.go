package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/privacy"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// asTenant runs fn on the runtime role's pool in a transaction scoped like maturad's (tenant, or operator when
// tid is empty), so tests can check row-level security and set up states the API refuses.
func asTenant(t *testing.T, pool *pgxpool.Pool, tid string, fn func(pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		scope := "tenant"
		if tid == "" {
			scope = "operator"
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('matura.tenant_id', $1, true), set_config('matura.scope', $2, true)`,
			tid, scope); err != nil {
			return err
		}
		return fn(tx)
	})
}

// jsonOf decodes v's JSON form into plain maps and slices, so an API response and a bundle compare field by field.
func jsonOf(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// checkChain recomputes a chain from its anchor the way an external verifier would: each event links to the one
// before, unredacted events recompute to their hash, and the last one is the head.
func checkChain(t *testing.T, anchorSeq int64, anchorHash string, headSeq int64, headHash string, events []store.AuditEvent) {
	t.Helper()
	prev, last := anchorHash, anchorSeq
	for _, e := range events {
		if e.Seq != last+1 || e.PrevHash != prev {
			t.Fatalf("event %d does not follow %d (%s)", e.Seq, last, prev)
		}
		if !e.Redacted {
			if h, err := e.ComputeHash(); err != nil || h != e.Hash {
				t.Fatalf("event %d (%s) does not recompute: %v", e.Seq, e.Action, err)
			}
		}
		prev, last = e.Hash, e.Seq
	}
	if last != headSeq || prev != headHash {
		t.Fatalf("chain ends at %d %s, head is %d %s", last, prev, headSeq, headHash)
	}
}

// TestTenantExport: owners (not admins) export a tenant; the worker builds the bundle; it round-trips against the
// API's own view, carries a chain that verifies, is downloadable until it expires, and other tenants cannot reach it.
func TestTenantExport(t *testing.T) {
	srv, st, _, pool := setupPool(t)
	worker := &privacy.Worker{Store: st}
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	globex := carol.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	aid, gid := acme["id"].(string), globex["id"].(string)
	base := "/v1/tenants/" + aid
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	alice.must(http.StatusOK, "PUT", base+"/apps/devflow", nil)
	alice.must(http.StatusCreated, "POST", base+"/workspaces", map[string]any{"name": "Research"})
	alice.must(http.StatusCreated, "POST", base+"/grants", map[string]any{"app": "devflow", "user_id": bob.user, "role": "admin"})
	alice.must(http.StatusCreated, "POST", base+"/invitations", map[string]any{"email": "dave@example.test"})
	alice.must(http.StatusOK, "PUT", base+"/security-policy", map[string]any{"require_mfa": true,
		"allowed_email_domains": []string{"example.test"}})

	bob.must(http.StatusForbidden, "POST", base+"/exports", nil) // admins cannot export
	carol.must(http.StatusNotFound, "POST", base+"/exports", nil)
	exp := alice.must(http.StatusAccepted, "POST", base+"/exports", nil)
	eid := exp["id"].(string)
	if exp["state"] != "queued" {
		t.Fatalf("new export: %v", exp)
	}
	alice.must(http.StatusConflict, "POST", base+"/exports", nil) // one at a time
	alice.must(http.StatusConflict, "GET", base+"/exports/"+eid+"/download", nil)
	gexp := carol.must(http.StatusAccepted, "POST", "/v1/tenants/"+gid+"/exports", nil)

	if err := worker.Exports(ctx); err != nil {
		t.Fatal(err)
	}
	got := alice.must(http.StatusOK, "GET", base+"/exports/"+eid, nil)
	if got["state"] != "ready" || got["sha256"] == nil || got["expires_at"] == nil {
		t.Fatalf("export after the worker: %v", got)
	}
	if items := alice.must(http.StatusOK, "GET", base+"/exports", nil)["items"].([]any); len(items) != 1 {
		t.Fatalf("exports list: %v", items)
	}

	// other tenants: not through the API, not through the database
	carol.must(http.StatusNotFound, "GET", base+"/exports/"+eid, nil)
	carol.must(http.StatusNotFound, "GET", base+"/exports/"+eid+"/download", nil)
	carol.must(http.StatusNotFound, "GET", "/v1/tenants/"+gid+"/exports/"+eid, nil)
	alice.must(http.StatusNotFound, "GET", base+"/exports/"+gexp["id"].(string), nil)
	err := asTenant(t, pool, gid, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_export WHERE tenant_id = $1`, aid).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("globex's context sees %d of acme's exports", n)
		}
		_, err := tx.Exec(ctx, `UPDATE tenant_export SET state = 'queued' WHERE id = $1`, eid)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	status, h, body := alice.raw("GET", base+"/exports/"+eid+"/download", nil)
	if status != http.StatusOK || h.Get("Matura-Export-SHA256") != got["sha256"] {
		t.Fatalf("download: %d %v %s", status, h, body)
	}
	var bundle store.TenantBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Format != store.ExportFormat || bundle.ExportID.String() != eid {
		t.Fatalf("bundle header: %s %s", bundle.Format, bundle.ExportID)
	}
	// round trip: the bundle says what the API says
	for _, c := range []struct {
		name string
		api  any
		got  any
	}{
		{"tenant", alice.must(http.StatusOK, "GET", base, nil), bundle.Tenant},
		{"workspaces", alice.must(http.StatusOK, "GET", base+"/workspaces", nil)["items"], bundle.Workspaces},
		{"members", alice.must(http.StatusOK, "GET", base+"/members", nil)["items"], bundle.Members},
		{"grants", alice.must(http.StatusOK, "GET", base+"/grants", nil)["items"], bundle.Grants},
		{"invitations", alice.must(http.StatusOK, "GET", base+"/invitations", nil)["items"], bundle.Invitations},
		{"placements", alice.must(http.StatusOK, "GET", base+"/placements", nil)["items"], bundle.Placements},
		{"security policy", alice.must(http.StatusOK, "GET", base+"/security-policy", nil), bundle.SecurityPolicy},
		{"retention", alice.must(http.StatusOK, "GET", base+"/retention", nil), bundle.Retention},
	} {
		if a, b := jsonOf(t, c.api), jsonOf(t, c.got); !reflect.DeepEqual(a, b) {
			t.Errorf("%s: API %v\nbundle %v", c.name, a, b)
		}
	}
	if len(bundle.Workspaces) != 2 || len(bundle.Members) != 2 || len(bundle.Grants) != 1 || len(bundle.Invitations) != 1 {
		t.Fatalf("bundle contents: %d workspaces, %d members, %d grants, %d invitations", len(bundle.Workspaces),
			len(bundle.Members), len(bundle.Grants), len(bundle.Invitations))
	}
	if len(bundle.Roles) == 0 || bundle.Roles[0].App != "devflow" {
		t.Fatalf("roles used: %v", bundle.Roles)
	}
	if strings.Contains(string(body), "token_hash") || strings.Contains(string(body), "password") {
		t.Fatal("the bundle carries a secret")
	}
	checkChain(t, bundle.Audit.AnchorSeq, bundle.Audit.AnchorHash, bundle.Audit.HeadSeq, bundle.Audit.HeadHash,
		bundle.Audit.Events)
	if n := len(bundle.Audit.Events); n == 0 || bundle.Audit.Events[n-1].Action != "tenant_export.requested" {
		t.Fatalf("the bundle's chain should end with the export's request: %d events", n)
	}

	page := alice.must(http.StatusOK, "GET", base+"/audit?action=tenant_export.", nil)
	if a := actions(auditItems(t, page)); !reflect.DeepEqual(a, []string{"tenant_export.downloaded",
		"tenant_export.completed", "tenant_export.requested"}) {
		t.Fatalf("export audit: %v", a)
	}
	if v := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil); v["ok"] != true {
		t.Fatalf("verify: %v", v)
	}

	// expired bundles are cleared and answer 410
	err = asTenant(t, pool, "", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant_export SET expires_at = now() - interval '1 second' WHERE id = $1`, eid)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	alice.must(http.StatusGone, "GET", base+"/exports/"+eid+"/download", nil)
	if err := worker.Exports(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alice.must(http.StatusOK, "GET", base+"/exports/"+eid, nil); got["state"] != "expired" {
		t.Fatalf("after expiry: %v", got)
	}
	err = asTenant(t, pool, aid, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_export WHERE id = $1 AND bundle IS NOT NULL`, eid).Scan(&n)
		if n != 0 {
			t.Error("an expired export kept its bundle")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// a bundle over the cap fails the export instead
	defer func(n int) { store.MaxExportBytes = n }(store.MaxExportBytes)
	store.MaxExportBytes = 100
	exp2 := alice.must(http.StatusAccepted, "POST", base+"/exports", nil)
	if err := worker.Exports(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alice.must(http.StatusOK, "GET", base+"/exports/"+exp2["id"].(string), nil); got["state"] != "failed" ||
		!strings.Contains(got["error"].(string), "more than") {
		t.Fatalf("oversized export: %v", got)
	}
}

type fakeDirectory struct {
	mu      sync.Mutex
	deleted []uuid.UUID
	err     error
}

func (d *fakeDirectory) DeleteUser(_ context.Context, id uuid.UUID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deleted = append(d.deleted, id)
	return d.err
}

// TestUserDataRights: a user exports everything Matura holds about them, cannot erase themselves while the only
// owner of a tenant, and once erased is gone from tenants, grants and invitations, shows as a pseudonym everywhere
// the audit log is read, and every chain still verifies.
func TestUserDataRights(t *testing.T) {
	st := store.New(testdb.New(t))
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDirectory{}
	server := api.New(st, api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetUserDirectory(dir)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)

	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New(), name: "Bob Quixote"}
	carol := client{t: t, srv: srv, user: ids.New()}
	bobEmail := emailOf(bob)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	globex := carol.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	aid, gid := acme["id"].(string), globex["id"].(string)
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants", map[string]any{"app": "devflow", "user_id": bob.user, "role": "admin"})
	bob.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "Bob's corner"})
	carol.must(http.StatusCreated, "POST", "/v1/tenants/"+gid+"/invitations", map[string]any{"email": bobEmail})
	bobco := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "bobco", "name": "Bobco"})
	bid := bobco["id"].(string)

	// the user's own export
	status, h, body := bob.raw("GET", "/v1/me/export", nil)
	if status != http.StatusOK || !strings.Contains(h.Get("Content-Disposition"), "attachment") {
		t.Fatalf("my export: %d %s", status, body)
	}
	var mine store.UserData
	if err := json.Unmarshal(body, &mine); err != nil {
		t.Fatal(err)
	}
	if mine.Format != store.UserExportFormat || mine.Profile.Email == nil || *mine.Profile.Email != bobEmail ||
		len(mine.Memberships) != 2 || len(mine.Invitations) != 1 || len(mine.Audit.Events) == 0 {
		t.Fatalf("my export: %+v", mine)
	}
	grants := 0
	for _, g := range mine.Grants {
		if g.SubjectID != bob.user {
			t.Fatalf("someone else's grant in my export: %+v", g)
		}
		grants++
	}
	if grants != 1 {
		t.Fatalf("grants in my export: %+v", mine.Grants)
	}
	for _, e := range mine.Audit.Events {
		if e.Actor.ID == nil || *e.Actor.ID != bob.user {
			t.Fatalf("an event by someone else in my export: %+v", e)
		}
	}
	if items := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant=installation&action=user.exported", nil)); len(items) != 1 {
		t.Fatalf("user.exported: %v", items)
	}

	// the only owner of a tenant cannot be erased, and is told which
	_, out := bob.do("DELETE", "/v1/me", nil)
	if out["status"] != float64(http.StatusConflict) || !strings.HasSuffix(out["type"].(string), "/last-owner") ||
		!reflect.DeepEqual(out["tenants"], []any{bid}) {
		t.Fatalf("last owner: %v", out)
	}
	op.must(http.StatusConflict, "DELETE", "/admin/v1/users/"+bob.user.String(), nil)
	bob.must(http.StatusOK, "GET", "/v1/me", nil) // nothing changed
	bob.must(http.StatusCreated, "POST", "/v1/tenants/"+bid+"/members", map[string]any{"user_id": alice.user, "tenant_role": "owner"})

	bob.must(http.StatusNoContent, "DELETE", "/v1/me", nil)
	if !reflect.DeepEqual(dir.deleted, []uuid.UUID{bob.user}) {
		t.Fatalf("identity provider deletions: %v", dir.deleted)
	}
	bob.must(http.StatusForbidden, "GET", "/v1/me", nil)
	if u := op.must(http.StatusOK, "GET", "/admin/v1/users/"+bob.user.String(), nil); u["status"] != "deleted" || u["email"] != nil {
		t.Fatalf("erased user: %v", u)
	}
	for _, tid := range []string{aid, bid} {
		for _, m := range alice.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/members", nil)["items"].([]any) {
			if m.(map[string]any)["user_id"] == bob.user.String() {
				t.Fatalf("still a member of %s", tid)
			}
		}
	}
	if g := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/grants?user_id="+bob.user.String(), nil)["items"].([]any); len(g) != 0 {
		t.Fatalf("grants left: %v", g)
	}
	inv := carol.must(http.StatusOK, "GET", "/v1/tenants/"+gid+"/invitations", nil)["items"].([]any)[0].(map[string]any)
	if inv["state"] != "revoked" || inv["email"] != store.Pseudonym(bob.user) {
		t.Fatalf("invitation to the erased address: %v", inv)
	}

	// apps hear about it through contract events
	types := map[string]bool{}
	for _, e := range auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?limit=1000", nil)) {
		types[e["action"].(string)] = true
	}
	for _, want := range []string{"user.deleted", "membership.removed", "grant.revoked", "invitation.revoked"} {
		if !types[want] {
			t.Errorf("no %s event", want)
		}
	}

	// every reader shows the pseudonym; nothing shows the address or the name
	pseudonym := store.Pseudonym(bob.user)
	leaks := func(where string, b []byte) {
		t.Helper()
		if strings.Contains(string(b), bobEmail) || strings.Contains(strings.ToLower(string(b)), "quixote") {
			t.Errorf("%s still shows the erased user: %s", where, b)
		}
	}
	for _, path := range []string{"/v1/tenants/" + aid + "/audit?limit=1000", "/v1/tenants/" + aid + "/audit/export",
		"/v1/tenants/" + gid + "/audit/export"} {
		c := alice
		if strings.Contains(path, gid) {
			c = carol
		}
		_, _, b := c.raw("GET", path, nil)
		leaks(path, b)
	}
	_, _, b := op.raw("GET", "/admin/v1/audit?limit=1000", nil)
	leaks("operator audit", b)
	if !strings.Contains(string(b), pseudonym) || !strings.Contains(string(b), `"redacted":true`) {
		t.Fatal("the operator's audit view does not show the pseudonym")
	}
	byBob := auditItems(t, alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit?actor="+bob.user.String(), nil))
	if len(byBob) == 0 || byBob[0]["actor"].(map[string]any)["email"] != pseudonym {
		t.Fatalf("events by the erased user: %v", byBob)
	}
	if items := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?actor="+bobEmail, nil)); len(items) != 0 {
		t.Fatalf("the old address still finds events: %v", items)
	}

	// hashed rows were not edited: every chain verifies
	for _, path := range []string{"/admin/v1/audit:verify", "/admin/v1/audit:verify?tenant=" + aid,
		"/admin/v1/audit:verify?tenant=" + gid, "/admin/v1/audit:verify?tenant=" + bid} {
		if v := op.must(http.StatusOK, "GET", path, nil); v["ok"] != true {
			t.Fatalf("%s: %v", path, v)
		}
	}
	// and an exported chain still links, recomputing every event that was not pseudonymised
	ch := exportChain(t, alice, aid)
	redacted := 0
	for _, e := range ch {
		if e.Redacted {
			redacted++
		}
	}
	if redacted == 0 {
		t.Fatal("no exported event was pseudonymised")
	}
	v := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/audit:verify", nil)
	checkChain(t, 0, strings.Repeat("0", 64), int64(v["head_seq"].(float64)), v["head_hash"].(string), ch)

	// erasing again is not found; a directory failure does not undo the erasure
	op.must(http.StatusNotFound, "DELETE", "/admin/v1/users/"+bob.user.String(), nil)
	dir.err = errors.New("keycloak unreachable")
	dave := client{t: t, srv: srv, user: ids.New()}
	dave.must(http.StatusOK, "GET", "/v1/me", nil)
	op.must(http.StatusNoContent, "DELETE", "/admin/v1/users/"+dave.user.String(), nil)
	if items := auditItems(t, op.must(http.StatusOK, "GET", "/admin/v1/audit?action=user.directory_delete_failed", nil)); len(items) != 1 {
		t.Fatalf("directory failure not audited: %v", items)
	}
}

// TestAuditRetention: retention and legal hold are owners' to set; the purge removes only events past retention,
// never under hold, moves the chain's anchor so verification still passes, and the runtime role can neither delete
// audit events nor move the anchor itself.
func TestAuditRetention(t *testing.T) {
	srv, st, _, pool := setupPool(t)
	worker := &privacy.Worker{Store: st}
	ctx := context.Background()
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	globex := carol.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	aid, gid := acme["id"].(string), globex["id"].(string)
	base := "/v1/tenants/" + aid
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	alice.must(http.StatusCreated, "POST", base+"/workspaces", map[string]any{"name": "One"})

	r := alice.must(http.StatusOK, "GET", base+"/retention", nil)
	if r["retention_days"] != float64(400) || r["legal_hold"] != false || r["version"] != float64(0) {
		t.Fatalf("default retention: %v", r)
	}
	bob.must(http.StatusOK, "GET", base+"/retention", nil)
	bob.must(http.StatusForbidden, "PUT", base+"/retention", map[string]any{"retention_days": 90})
	carol.must(http.StatusNotFound, "GET", base+"/retention", nil)
	carol.must(http.StatusNotFound, "PUT", base+"/retention", map[string]any{"retention_days": 90})
	alice.must(http.StatusUnprocessableEntity, "PUT", base+"/retention", map[string]any{"retention_days": 10})
	alice.must(http.StatusUnprocessableEntity, "PUT", base+"/retention", map[string]any{"retention_days": 90, "legal_hold": true})
	r = alice.must(http.StatusOK, "PUT", base+"/retention", map[string]any{"retention_days": 90, "legal_hold": true,
		"legal_hold_reason": "litigation 2026-17"})
	if r["legal_hold"] != true || r["legal_hold_reason"] != "litigation 2026-17" {
		t.Fatalf("hold: %v", r)
	}

	// shorten retention to nothing behind the API's back, as if every event were old
	expireAll := func() {
		t.Helper()
		if err := asTenant(t, pool, aid, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE audit_retention SET retention_days = 0 WHERE tenant_id = $1`, aid)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	expireAll()
	before := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil)
	gBefore := carol.must(http.StatusOK, "GET", "/v1/tenants/"+gid+"/audit:verify", nil)
	if purged, err := worker.Purge(ctx); err != nil || len(purged) != 0 {
		t.Fatalf("purge under legal hold: %v %v", purged, err)
	}
	if v := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil); v["events"] != before["events"] {
		t.Fatalf("legal hold did not stop the purge: %v", v)
	}

	alice.must(http.StatusOK, "PUT", base+"/retention", map[string]any{"retention_days": 30, "legal_hold": false})
	expireAll()
	purged, err := worker.Purge(ctx)
	if err != nil || len(purged) != 1 || purged[0].TenantID.String() != aid || purged[0].Purged == 0 {
		t.Fatalf("purge: %v %v", purged, err)
	}
	v := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil)
	if v["ok"] != true || v["anchor_seq"] != float64(purged[0].AnchorSeq) || v["anchor_hash"] != purged[0].AnchorHash ||
		v["events"] != float64(1) {
		t.Fatalf("verify after purge: %v (purged %+v)", v, purged[0])
	}
	items := auditItems(t, alice.must(http.StatusOK, "GET", base+"/audit", nil))
	if a := actions(items); !reflect.DeepEqual(a, []string{"audit.purged"}) {
		t.Fatalf("events left: %v", a)
	}
	if r := alice.must(http.StatusOK, "GET", base+"/retention", nil); r["anchor_seq"] != float64(purged[0].AnchorSeq) {
		t.Fatalf("retention after purge: %v", r)
	}
	// another tenant's chain is untouched
	if g := carol.must(http.StatusOK, "GET", "/v1/tenants/"+gid+"/audit:verify", nil); g["events"] != gBefore["events"] || g["ok"] != true {
		t.Fatalf("globex after acme's purge: %v", g)
	}
	// the chain keeps growing from the anchor, and an exported chain checks from it
	alice.must(http.StatusCreated, "POST", base+"/workspaces", map[string]any{"name": "Two"})
	ch := exportChain(t, alice, aid) // records audit.exported first
	v = alice.must(http.StatusOK, "GET", base+"/audit:verify", nil)
	if v["ok"] != true || v["events"] != float64(3) {
		t.Fatalf("verify after new events: %v", v)
	}
	checkChain(t, purged[0].AnchorSeq, purged[0].AnchorHash, int64(v["head_seq"].(float64)), v["head_hash"].(string), ch)

	// the database itself refuses shortcuts by the runtime role
	denied := func(what string, err error) {
		t.Helper()
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Errorf("%s: want permission denied, got %v", what, err)
		}
	}
	denied("delete", asTenant(t, pool, aid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id = $1`, aid)
		return err
	}))
	denied("move anchor", asTenant(t, pool, aid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_chain SET anchor_seq = anchor_seq + 1 WHERE chain = $1`, aid)
		return err
	}))
	denied("purge another tenant", asTenant(t, pool, gid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM matura_audit_purge($1)`, aid)
		return err
	}))
	if v := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil); v["ok"] != true {
		t.Fatalf("verify at the end: %v", v)
	}
}
