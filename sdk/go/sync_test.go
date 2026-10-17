package matura_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	matura "github.com/marunsct/Platform/sdk/go"
)

// fakeMaturad serves the app endpoints the SDK calls, recording each request.
type fakeMaturad struct {
	mu      sync.Mutex
	calls   []string
	changes func(cursor string) (int, any)
}

func (f *fakeMaturad) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "notes" || p != "secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	tenant := map[string]any{"id": T1, "slug": "acme", "name": "Acme", "kind": "company", "status": "active",
		"data_mode_default": "shared", "version": 10}
	switch r.URL.Path {
	case "/v1/apps/notes/snapshot":
		if r.URL.Query().Get("tenant") == "" {
			reply(200, map[string]any{"cursor": 7, "tenants": []string{T1}, "roles": []any{map[string]any{
				"name": "editor", "permissions": []string{"note.read"}, "version": 3}}})
			return
		}
		reply(200, map[string]any{"cursor": 7, "tenant": tenant, "workspaces": []any{}, "users": []any{map[string]any{
			"id": U1, "email": "ada@example.test", "status": "active", "version": 4}},
			"memberships": []any{map[string]any{"tenant_id": T1, "user_id": U1, "tenant_role": "member",
				"status": "active", "version": 5}}, "grants": []any{},
			"placement": map[string]any{"tenant_id": T1, "mode": "schema", "state": "ready", "version": 6},
			"roles":     []any{}})
	case "/v1/apps/notes/changes":
		reply(f.changes(r.URL.Query().Get("cursor")))
	case "/v1/apps/notes/placements/" + T1:
		body, _ := io.ReadAll(r.Body)
		reply(200, map[string]any{"tenant_id": T1, "mode": "schema", "state": "ready", "manager": "app",
			"location_label": string(body), "version": 6})
	case "/v1/apps/notes/placements/" + T1 + "/credentials":
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply(200, map[string]any{"host": "db", "port": 5432, "user": "notes_" + req["purpose"],
			"expires_at": "2026-10-17T10:00:00Z"})
	case "/v1/apps/notes/placements/" + T1 + ":ready", "/v1/apps/notes/placements/" + T1 + ":deleted":
		reply(200, map[string]any{"tenant_id": T1, "state": "ready"})
	default:
		reply(404, map[string]any{"detail": "no placement for this tenant"})
	}
}

func change(id string, version int64, role string) map[string]any {
	return map[string]any{"id": id, "type": "matura.membership.updated", "data": map[string]any{
		"object": "membership", "version": version, "membership": map[string]any{"tenant_id": T1, "user_id": U1,
			"tenant_role": role, "status": "active"}}}
}

func TestSyncBootstrapAndCatchUp(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	f := &fakeMaturad{}
	expired := true
	f.changes = func(cursor string) (int, any) {
		switch cursor {
		case "7":
			if expired { // the first read finds the cursor too old: bootstrap again
				expired = false
				return 410, map[string]any{"detail": "cursor expired"}
			}
			return 200, map[string]any{"items": []any{change("evt_8", 8, "admin"), nil}, "next_cursor": "8", "has_more": true}
		case "8":
			return 200, map[string]any{"items": []any{change("evt_8", 8, "admin"), change("evt_9", 9, "owner")},
				"next_cursor": "9", "has_more": false}
		}
		return 200, map[string]any{"items": []any{}, "next_cursor": cursor, "has_more": false}
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s := &matura.Sync{Client: matura.NewClient(srv.URL+"/", "notes", "secret"), App: "notes",
		Contract: matura.NewContract(), DB: pool}
	n, err := s.CatchUp(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("applied = %d, want 2 (evt_8 once, evt_9)", n)
	}
	got := rowsJSON(t, pool, `SELECT t.data_mode, t.placement_version, m.tenant_role, m.version,
		(SELECT cursor FROM matura_sync_cursor) AS cursor, (SELECT count(*) FROM matura_app_role) AS roles
		FROM matura_tenant t JOIN matura_membership m ON m.tenant_id = t.id`)
	if fmt.Sprint(got) != "[map[cursor:9 data_mode:schema placement_version:6 roles:1 tenant_role:owner version:9]]" {
		t.Fatalf("rows = %v", got)
	}
	if n, err := s.CatchUp(ctx, 0); err != nil || n != 0 {
		t.Fatalf("again: %d, %v", n, err)
	}
	want := fmt.Sprint([]string{
		"GET /v1/apps/notes/snapshot", "GET /v1/apps/notes/snapshot?tenant=" + T1,
		"GET /v1/apps/notes/changes?cursor=7&limit=500",
		"GET /v1/apps/notes/snapshot", "GET /v1/apps/notes/snapshot?tenant=" + T1,
		"GET /v1/apps/notes/changes?cursor=7&limit=500", "GET /v1/apps/notes/changes?cursor=8&limit=500",
		"GET /v1/apps/notes/changes?cursor=9&limit=500",
	})
	if fmt.Sprint(f.calls) != want {
		t.Fatalf("calls:\n%v\nwant\n%v", f.calls, want)
	}
}

func TestSnapshotEvents(t *testing.T) {
	var s matura.Snapshot
	err := json.Unmarshal([]byte(`{"cursor":"12","placement":{"tenant_id":"t","mode":"schema"},
		"grants":[{"id":"g","version":5}],"tenant":null}`), &s)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range matura.SnapshotEvents(&s) {
		got = append(got, fmt.Sprint(e.Type, " ", e.Data.Version))
	}
	if s.Cursor != "12" || fmt.Sprint(got) != "[matura.grant.added 5 matura.placement.updated 0]" {
		t.Fatalf("cursor %q, events %v", s.Cursor, got)
	}
}

func TestPlacementCalls(t *testing.T) {
	f := &fakeMaturad{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	c := matura.NewClient(srv.URL, "notes", "secret")
	p, err := c.Placement(ctx, "notes", T1)
	if err != nil || p.State != "ready" || p.Mode != "schema" || p.Version != 6 {
		t.Fatalf("placement = %+v, %v", p, err)
	}
	p, err = c.RegisterPlacement(ctx, "notes", T1, matura.StorageRegistration{LocationLabel: "eu-1 / db",
		SchemaName: "t_acme"})
	if err != nil || p.LocationLabel != `{"location_label":"eu-1 / db","schema_name":"t_acme"}` {
		t.Fatalf("register = %+v, %v", p, err)
	}
	for _, purpose := range []string{"", matura.PurposeMigrate} {
		cr, err := c.Credentials(ctx, "notes", T1, purpose)
		if err != nil || cr.Port != 5432 || cr.ExpiresAt.IsZero() {
			t.Fatalf("credentials = %+v, %v", cr, err)
		}
		if want := map[string]string{"": "notes_runtime", "migrate": "notes_migrate"}[purpose]; cr.User != want {
			t.Fatalf("user = %s, want %s", cr.User, want)
		}
	}
	if _, err := c.PlacementReady(ctx, "notes", T1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PlacementDeleted(ctx, "notes", T1); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprint([]string{
		"GET /v1/apps/notes/placements/" + T1, "PUT /v1/apps/notes/placements/" + T1,
		"POST /v1/apps/notes/placements/" + T1 + "/credentials", "POST /v1/apps/notes/placements/" + T1 + "/credentials",
		"POST /v1/apps/notes/placements/" + T1 + ":ready", "POST /v1/apps/notes/placements/" + T1 + ":deleted",
	})
	if fmt.Sprint(f.calls) != want {
		t.Fatalf("calls = %v", f.calls)
	}
	_, err = c.Placement(ctx, "notes", "missing")
	var apiErr *matura.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Detail != "no placement for this tenant" {
		t.Fatalf("err = %v", err)
	}
	// the change feed maps 410 to ErrCursorExpired; other endpoints do not
	f.changes = func(string) (int, any) { return 410, map[string]any{"detail": "gone"} }
	if _, err := c.Changes(ctx, "notes", "1", 0); !errors.Is(err, matura.ErrCursorExpired) {
		t.Fatalf("changes: %v", err)
	}
	if _, err := matura.NewClient(srv.URL, "notes", "wrong").Snapshot(ctx, "notes", ""); !errors.As(err, &apiErr) ||
		apiErr.Status != 401 {
		t.Fatalf("bad secret: %v", err)
	}
}
