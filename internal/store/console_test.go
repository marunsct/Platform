package store_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/marunsct/Platform/internal/store"
)

// TestSupportAccessIsolated: support access rows are tenant-owned; another tenant, and a session with no tenant,
// cannot see them, and a tenant cannot decide another tenant's request.
func TestSupportAccessIsolated(t *testing.T) {
	st, pool := setup(t)
	a := user(t, st, "a@acme.test")
	b := user(t, st, "b@globex.test")
	op := user(t, st, "op@matura.test")
	acme := tenant(t, st, a, "acme")
	globex := tenant(t, st, b, "globex")

	req, err := st.RequestSupportAccess(ctx, store.Scope{UserID: op, Operator: true}, acme.ID, op, "ticket 42", 30)
	if err != nil || req.State != "pending" {
		t.Fatalf("request: %v %v", req, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM support_access`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("visible without a tenant: %d %v", n, err)
	}
	if got, err := st.ListSupportAccess(ctx, store.Scope{UserID: b}, globex.ID); err != nil || len(got) != 0 {
		t.Fatalf("globex sees %v %v", got, err)
	}
	if got, err := st.ListSupportAccess(ctx, store.Scope{UserID: a}, acme.ID); err != nil || len(got) != 1 {
		t.Fatalf("acme sees %v %v", got, err)
	}
	// globex's scope with acme's request id: not found
	if _, err := st.DecideSupportAccess(ctx, store.Scope{UserID: b}, globex.ID, req.ID, b, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
	if _, err := st.UseSupportAccess(ctx, acme.ID, op); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pending access used: %v", err)
	}
}

// TestLimitsParse: the enforced keys are type-checked; other keys are kept for apps.
func TestLimitsParse(t *testing.T) {
	if _, err := store.ParseLimits(json.RawMessage(`{"max_members": "ten"}`)); err == nil {
		t.Fatal("a string max_members was accepted")
	}
	if _, err := store.ParseLimits(json.RawMessage(`[1]`)); err == nil {
		t.Fatal("a list was accepted as limits")
	}
	l, err := store.ParseLimits(json.RawMessage(`{"max_members": 3, "apps": [], "runs_per_month": 100}`))
	if err != nil || *l.MaxMembers != 3 || l.Apps == nil || len(*l.Apps) != 0 || l.MaxWorkspaces != nil {
		t.Fatalf("parsed %+v %v", l, err)
	}
}
