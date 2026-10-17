package api_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/lifecycle"
)

func (c client) problem(want int, typ, method, path string, body any) map[string]any {
	c.t.Helper()
	code, out := c.do(method, path, body)
	if code != want || out["type"] != "https://matura.dev/problems/"+typ {
		c.t.Fatalf("%s %s: %d %v, want %d %s", method, path, code, out, want, typ)
	}
	return out
}

type tenantEvent struct{ typ, status string }

// tenantEvents returns the tenant's lifecycle events from the outbox, oldest first.
func tenantEvents(t *testing.T, pool *pgxpool.Pool, tid string) []tenantEvent {
	t.Helper()
	ctx := context.Background()
	var out []tenantEvent
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('matura.scope', 'operator', true)`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT type, payload->>'status' FROM outbox WHERE tenant_id = $1
			AND type LIKE 'matura.tenant.%' ORDER BY id`, tid)
		if err != nil {
			return err
		}
		var e tenantEvent
		_, err = pgx.ForEachRow(rows, []any{&e.typ, &e.status}, func() error { out = append(out, e); return nil })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func lastEvent(t *testing.T, pool *pgxpool.Pool, tid string) tenantEvent {
	t.Helper()
	ev := tenantEvents(t, pool, tid)
	return ev[len(ev)-1]
}

// TestTenantSuspension: a suspended tenant refuses sign-in and its API to everyone but operators; resuming
// restores both, and each change is an event apps receive.
func TestTenantSuspension(t *testing.T) {
	srv, _, _, pool := setupPool(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	other := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "other", "name": "Other"})
	aid, oid := acme["id"].(string), other["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+oid+"/apps/devflow", nil)
	ask := func(tenant string) (int, map[string]any) {
		return tokenContext(t, srv.URL, internalToken, map[string]any{"user_id": alice.user, "client_id": "devflow",
			"tenant": tenant})
	}
	if code, c := ask("acme"); code != 200 || c["tid"] != aid {
		t.Fatalf("before suspension: %d %v", code, c)
	}

	// members cannot suspend; operators must give a reason
	alice.must(http.StatusForbidden, "POST", "/admin/v1/tenants/"+aid+":suspend", map[string]any{"reason": "x"})
	op.problem(http.StatusUnprocessableEntity, "invalid", "POST", "/admin/v1/tenants/"+aid+":suspend", nil)
	op.must(http.StatusNotFound, "POST", "/admin/v1/tenants/"+aid+":explode", nil)
	got := op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+aid+":suspend", map[string]any{"reason": "unpaid invoice"})
	if got["status"] != "suspended" || got["status_reason"] != "unpaid invoice" {
		t.Fatalf("suspended: %v", got)
	}
	if ev := lastEvent(t, pool, aid); ev != (tenantEvent{"matura.tenant.suspended", "suspended"}) {
		t.Fatalf("event: %v", ev)
	}

	// sign-in into acme is refused, owners included; with no tenant named the active one is chosen
	if code, c := ask("acme"); code != http.StatusForbidden || c["error_description"] != "tenant_suspended" {
		t.Fatalf("token for suspended tenant: %d %v", code, c)
	}
	if code, c := ask(""); code != 200 || c["tid"] != oid {
		t.Fatalf("no tenant named: %d %v", code, c)
	}
	// the tenant API refuses its members; operators still see the record
	for _, path := range []string{"", "/members", "/workspaces", "/entitlements"} {
		alice.problem(http.StatusForbidden, "tenant-suspended", "GET", "/v1/tenants/"+aid+path, nil)
	}
	alice.problem(http.StatusForbidden, "tenant-suspended", "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "x"})
	if got := op.must(http.StatusOK, "GET", "/v1/tenants/"+aid, nil); got["status"] != "suspended" {
		t.Fatalf("operator view: %v", got)
	}
	// the user's tenant list still shows it, without the operator's reason
	for _, it := range alice.must(http.StatusOK, "GET", "/v1/me/tenants", nil)["items"].([]any) {
		if m := it.(map[string]any); m["id"] == aid && (m["status"] != "suspended" || m["status_reason"] != nil) {
			t.Fatalf("my tenants: %v", m)
		}
	}

	got = op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+aid+":resume", nil)
	if got["status"] != "active" || got["status_reason"] != nil {
		t.Fatalf("resumed: %v", got)
	}
	if ev := lastEvent(t, pool, aid); ev != (tenantEvent{"matura.tenant.reactivated", "active"}) {
		t.Fatalf("event: %v", ev)
	}
	if code, _ := ask("acme"); code != 200 {
		t.Fatalf("after resume: %d", code)
	}
	alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/members", nil)
	op.must(http.StatusNotFound, "POST", "/admin/v1/tenants/"+ids.New().String()+":resume", nil)

	// PATCH status does the same
	op.must(http.StatusOK, "PATCH", "/v1/tenants/"+aid, map[string]any{"status": "suspended", "reason": "abuse report"})
	alice.problem(http.StatusForbidden, "tenant-suspended", "GET", "/v1/tenants/"+aid+"/members", nil)
	op.must(http.StatusUnprocessableEntity, "PATCH", "/v1/tenants/"+aid, map[string]any{"status": "deleting"})
	op.must(http.StatusOK, "PATCH", "/v1/tenants/"+aid, map[string]any{"status": "active"})
}

// TestTenantDeletionGrace: deleting starts a grace period in which the tenant can be restored; the purger deletes
// it afterwards, apps are told to drop its data, and it is marked deleted when its storage is gone.
func TestTenantDeletionGrace(t *testing.T) {
	srv, st, _, pool := setupPool(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/invitations", map[string]any{"email": "dave@example.test"})

	// only owners (and operators) delete; only operators choose the grace period
	bob.must(http.StatusForbidden, "DELETE", "/v1/tenants/"+aid, nil)
	alice.must(http.StatusForbidden, "DELETE", "/v1/tenants/"+aid+"?grace_days=0", nil)
	got := alice.must(http.StatusAccepted, "DELETE", "/v1/tenants/"+aid, nil)
	purgeAfter, _ := time.Parse(time.RFC3339Nano, got["purge_after"].(string))
	if got["status"] != "pending_deletion" || time.Until(purgeAfter) < 29*24*time.Hour {
		t.Fatalf("pending deletion: %v", got)
	}
	// apps see it as suspended until the purge
	if ev := lastEvent(t, pool, aid); ev != (tenantEvent{"matura.tenant.suspended", "suspended"}) {
		t.Fatalf("event: %v", ev)
	}
	alice.must(http.StatusAccepted, "DELETE", "/v1/tenants/"+aid, nil) // again: no change
	if code, c := tokenContext(t, srv.URL, internalToken, map[string]any{"user_id": alice.user, "client_id": "devflow",
		"tenant": "acme"}); code != http.StatusForbidden || c["error_description"] != "tenant_pending_deletion" {
		t.Fatalf("token while pending deletion: %d %v", code, c)
	}
	alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid, nil)
	alice.problem(http.StatusForbidden, "tenant-pending-deletion", "GET", "/v1/tenants/"+aid+"/members", nil)
	bob.problem(http.StatusForbidden, "tenant-pending-deletion", "GET", "/v1/tenants/"+aid+"/workspaces", nil)

	purger := &lifecycle.Purger{Store: st}
	if n, _, err := purger.Round(ctx); err != nil || n != 0 {
		t.Fatalf("purged during the grace period: %d %v", n, err)
	}
	// admins cannot restore; the owner can
	bob.must(http.StatusForbidden, "POST", "/v1/tenants/"+aid+":restore", nil)
	if got := alice.must(http.StatusOK, "POST", "/v1/tenants/"+aid+":restore", nil); got["status"] != "active" || got["purge_after"] != nil {
		t.Fatalf("restored: %v", got)
	}
	if ev := lastEvent(t, pool, aid); ev != (tenantEvent{"matura.tenant.reactivated", "active"}) {
		t.Fatalf("event: %v", ev)
	}
	alice.must(http.StatusConflict, "POST", "/v1/tenants/"+aid+":restore", nil)
	alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/members", nil)

	// a suspended tenant deleted and restored is suspended again
	op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+aid+":suspend", map[string]any{"reason": "unpaid"})
	op.must(http.StatusAccepted, "DELETE", "/admin/v1/tenants/"+aid, nil)
	if got := op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+aid+":restore", nil); got["status"] != "suspended" ||
		got["status_reason"] != "unpaid" {
		t.Fatalf("restored a suspended tenant: %v", got)
	}
	op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+aid+":resume", nil)

	// an operator deletes with no grace: the purger deletes it at once
	got = op.must(http.StatusAccepted, "DELETE", "/admin/v1/tenants/"+aid+"?grace_days=0&reason=customer+request", nil)
	if got["status"] != "pending_deletion" || got["status_reason"] != "customer request" {
		t.Fatalf("operator delete: %v", got)
	}
	op.must(http.StatusBadRequest, "DELETE", "/admin/v1/tenants/"+aid+"?grace_days=-1", nil)
	if n, _, err := purger.Round(ctx); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if ev := lastEvent(t, pool, aid); ev != (tenantEvent{"matura.tenant.deleting", "deleting"}) {
		t.Fatalf("event: %v", ev)
	}
	got = op.must(http.StatusOK, "GET", "/v1/tenants/"+aid, nil)
	if got["status"] != "deleting" {
		t.Fatalf("after purge: %v", got)
	}
	op.must(http.StatusConflict, "POST", "/admin/v1/tenants/"+aid+":restore", nil)
	// the app's placement retires (the provisioner drops it once the app confirms; see TestPlatformManagedPlacements)
	pl := op.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/placements", nil)["items"].([]any)
	if len(pl) != 1 || pl[0].(map[string]any)["state"] != "retiring" {
		t.Fatalf("placements after purge: %v", pl)
	}
	var invState string
	_ = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, _ = tx.Exec(ctx, `SELECT set_config('matura.scope', 'operator', true)`)
		return tx.QueryRow(ctx, `SELECT state FROM invitation WHERE tenant_id = $1`, aid).Scan(&invState)
	})
	if invState != "revoked" {
		t.Fatalf("pending invitation after purge: %q", invState)
	}
	if _, done, _ := purger.Round(ctx); done != 0 {
		t.Fatal("marked deleted while a placement still holds data")
	}

	// a tenant with no placements is deleted in the same round
	empty := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "empty", "name": "Empty"})
	eid := empty["id"].(string)
	op.must(http.StatusAccepted, "DELETE", "/admin/v1/tenants/"+eid+"?grace_days=0", nil)
	if n, done, err := purger.Round(ctx); err != nil || n != 1 || done != 1 {
		t.Fatalf("purge empty tenant: %d %d %v", n, done, err)
	}
	if ev := tenantEvents(t, pool, eid); ev[len(ev)-1] != (tenantEvent{"matura.tenant.deleted", "deleted"}) {
		t.Fatalf("events: %v", ev)
	}
	alice.must(http.StatusNotFound, "GET", "/v1/tenants/"+eid, nil)
	op.must(http.StatusNotFound, "POST", "/admin/v1/tenants/"+eid+":suspend", map[string]any{"reason": "x"})
}

// TestEntitlements: plan limits, with per-tenant overrides, are enforced when members join, workspaces are created
// and apps are enabled, under concurrency too, and the tenant sees its limits and usage.
func TestEntitlements(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/plans/team", map[string]any{"limits": map[string]any{"max_members": "two"}})
	op.must(http.StatusOK, "PUT", "/admin/v1/plans/team", map[string]any{"name": "Team", "limits": map[string]any{
		"max_members": 2, "max_workspaces": 2, "apps": []string{"devflow"},
		"features": map[string]bool{"sso": false, "audit_export": true}}})

	alice := client{t: t, srv: srv, user: ids.New()}
	users := make([]client, 8)
	for i := range users {
		users[i] = client{t: t, srv: srv, user: ids.New()}
		users[i].must(http.StatusOK, "GET", "/v1/me", nil)
	}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	base := "/v1/tenants/" + aid

	// no plan: no limits
	if e := alice.must(http.StatusOK, "GET", base+"/entitlements", nil); e["plan"] != nil {
		t.Fatalf("no plan: %v", e)
	}
	alice.must(http.StatusForbidden, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "team"})
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "gold"})
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/tenants/"+aid+"/plan",
		map[string]any{"plan": "team", "overrides": map[string]any{"apps": "all"}})
	e := op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "team"})
	if e["plan"].(map[string]any)["id"] != "team" || e["limits"].(map[string]any)["max_members"] != 2.0 {
		t.Fatalf("plan set: %v", e)
	}

	// members: the owner and one more
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": users[0].user})
	out := alice.problem(http.StatusPaymentRequired, "plan-limit", "POST", base+"/members", map[string]any{"user_id": users[1].user})
	if out["limit"] != "max_members" || out["max"] != 2.0 || out["used"] != 2.0 {
		t.Fatalf("member limit: %v", out)
	}
	// accepting an invitation counts too
	inv := alice.must(http.StatusCreated, "POST", base+"/invitations", map[string]any{"email": users[1].user.String()[24:] + "@example.test"})
	token := inv["accept_url"].(string)[len("http://matura.test/invitations/accept?token="):]
	users[1].problem(http.StatusPaymentRequired, "plan-limit", "POST", "/v1/invitations:accept", map[string]any{"token": token})

	// workspaces: the default and one more
	alice.must(http.StatusCreated, "POST", base+"/workspaces", map[string]any{"name": "Lab"})
	if out := alice.problem(http.StatusPaymentRequired, "plan-limit", "POST", base+"/workspaces", map[string]any{"name": "More"}); out["limit"] != "max_workspaces" {
		t.Fatalf("workspace limit: %v", out)
	}
	// apps: only devflow
	alice.must(http.StatusOK, "PUT", base+"/apps/devflow", nil)
	if out := alice.problem(http.StatusPaymentRequired, "plan-limit", "PUT", base+"/apps/notes", nil); out["limit"] != "apps" {
		t.Fatalf("app limit: %v", out)
	}

	// overrides: one more member, unlimited workspaces, sso on, every app
	e = op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "team",
		"overrides": map[string]any{"max_members": 3, "max_workspaces": -1, "apps": []string{"*"}, "features": map[string]bool{"sso": true}}})
	lim := e["limits"].(map[string]any)
	if f := lim["features"].(map[string]any); lim["max_members"] != 3.0 || f["sso"] != true || f["audit_export"] != true {
		t.Fatalf("overridden: %v", e)
	}
	users[1].must(http.StatusOK, "POST", "/v1/invitations:accept", map[string]any{"token": token})
	alice.must(http.StatusCreated, "POST", base+"/workspaces", map[string]any{"name": "More"})
	alice.must(http.StatusOK, "PUT", base+"/apps/notes", nil)

	// the tenant sees limits and usage; outsiders see nothing
	e = users[0].must(http.StatusOK, "GET", base+"/entitlements", nil)
	usage := e["usage"].(map[string]any)
	if usage["members"] != 3.0 || usage["workspaces"] != 3.0 || len(usage["apps"].([]any)) != 2 ||
		e["plan_limits"].(map[string]any)["max_members"] != 2.0 {
		t.Fatalf("entitlements: %v", e)
	}
	users[7].must(http.StatusNotFound, "GET", base+"/entitlements", nil)

	// concurrent additions never exceed the limit
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "team",
		"overrides": map[string]any{"max_members": 5}})
	var wg sync.WaitGroup
	codes := make(chan int, 5)
	for _, u := range users[2:7] {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			code, _ := alice.do("POST", base+"/members", map[string]any{"user_id": id})
			codes <- code
		}(u.user)
	}
	wg.Wait()
	close(codes)
	added := 0
	for c := range codes {
		switch c {
		case http.StatusCreated:
			added++
		case http.StatusPaymentRequired:
		default:
			t.Fatalf("concurrent add: %d", c)
		}
	}
	if added != 2 {
		t.Fatalf("%d members added concurrently, want 2", added)
	}
	// a plan's overrides can be cleared again
	if e := op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "team", "overrides": nil}); e["limits"].(map[string]any)["max_members"] != 2.0 {
		t.Fatalf("cleared overrides: %v", e)
	}
	// no plan: no limits
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": nil})
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": users[7].user})
}

// TestSupportAccess: operators see a tenant's admin views only with time-boxed access the tenant approved (or
// allows without approval), read-only, and the tenant sees every request and use.
func TestSupportAccess(t *testing.T) {
	srv, _, _, pool := setupPool(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op2 := client{t: t, srv: srv, user: ids.New(), op: true}
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	globex := carol.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	aid, gid := acme["id"].(string), globex["id"].(string)
	base := "/v1/tenants/" + aid
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})

	// no access yet: operators keep the tenant record but not its contents
	op.must(http.StatusOK, "GET", base, nil)
	op.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)

	admin := "/admin/v1/tenants/" + aid + "/support-access"
	op.must(http.StatusUnprocessableEntity, "POST", admin, map[string]any{"reason": "ticket 7", "duration_minutes": 481})
	op.must(http.StatusUnprocessableEntity, "POST", admin, map[string]any{"reason": " ", "duration_minutes": 60})
	alice.must(http.StatusForbidden, "POST", admin, map[string]any{"reason": "x", "duration_minutes": 60})
	req := op.must(http.StatusCreated, "POST", admin, map[string]any{"reason": "ticket 7: members missing", "duration_minutes": 60})
	rid := req["id"].(string)
	if req["state"] != "pending" || req["expires_at"] != nil {
		t.Fatalf("request: %v", req)
	}
	op.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)

	// the tenant sees it; only an owner decides; another tenant cannot
	list := alice.must(http.StatusOK, "GET", base+"/support-access", nil)["items"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["reason"] != "ticket 7: members missing" ||
		list[0].(map[string]any)["operator_email"] == nil {
		t.Fatalf("tenant's list: %v", list)
	}
	bob.must(http.StatusOK, "GET", base+"/support-access", nil)
	bob.must(http.StatusForbidden, "POST", base+"/support-access/"+rid+":approve", nil)
	carol.must(http.StatusNotFound, "GET", base+"/support-access", nil)
	carol.must(http.StatusNotFound, "POST", "/v1/tenants/"+gid+"/support-access/"+rid+":approve", nil)
	if l := carol.must(http.StatusOK, "GET", "/v1/tenants/"+gid+"/support-access", nil)["items"].([]any); len(l) != 0 {
		t.Fatalf("globex sees acme's requests: %v", l)
	}
	alice.must(http.StatusNotFound, "POST", base+"/support-access/"+rid+":grant", nil)

	got := alice.must(http.StatusOK, "POST", base+"/support-access/"+rid+":approve", nil)
	if got["state"] != "active" || got["decided_by"] != alice.user.String() || got["expires_at"] == nil {
		t.Fatalf("approved: %v", got)
	}
	alice.must(http.StatusConflict, "POST", base+"/support-access/"+rid+":approve", nil)

	// read-only views for that operator only
	op.must(http.StatusOK, "GET", base+"/members", nil)
	op.must(http.StatusOK, "GET", base+"/workspaces", nil)
	op.must(http.StatusOK, "GET", base+"/support-access", nil)
	op.problem(http.StatusForbidden, "support-access-read-only", "POST", base+"/workspaces", map[string]any{"name": "x"})
	op.problem(http.StatusForbidden, "support-access-read-only", "DELETE", base+"/members/"+bob.user.String(), nil)
	op2.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)
	op.problem(http.StatusForbidden, "support-access-required", "GET", "/v1/tenants/"+gid+"/members", nil)
	list = alice.must(http.StatusOK, "GET", base+"/support-access", nil)["items"].([]any)
	if a := list[0].(map[string]any); a["uses"].(float64) < 3 || a["last_used_at"] == nil {
		t.Fatalf("uses not recorded: %v", a)
	}

	// the owner revokes it
	if got := alice.must(http.StatusOK, "POST", base+"/support-access/"+rid+":revoke", nil); got["state"] != "revoked" {
		t.Fatalf("revoked: %v", got)
	}
	op.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)

	// denied
	rid2 := op.must(http.StatusCreated, "POST", admin, map[string]any{"reason": "again", "duration_minutes": 30})["id"].(string)
	if got := alice.must(http.StatusOK, "POST", base+"/support-access/"+rid2+":deny", nil); got["state"] != "denied" {
		t.Fatalf("denied: %v", got)
	}
	op.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)

	// the operator ends their own access early; another operator cannot
	rid3 := op.must(http.StatusCreated, "POST", admin, map[string]any{"reason": "short look", "duration_minutes": 30})["id"].(string)
	alice.must(http.StatusOK, "POST", base+"/support-access/"+rid3+":approve", nil)
	op2.must(http.StatusNotFound, "POST", admin+"/"+rid3+":end", nil)
	if got := op.must(http.StatusOK, "POST", admin+"/"+rid3+":end", nil); got["state"] != "ended" {
		t.Fatalf("ended: %v", got)
	}
	op.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)

	// access expires
	rid4 := op.must(http.StatusCreated, "POST", admin, map[string]any{"reason": "expiry", "duration_minutes": 5})["id"].(string)
	alice.must(http.StatusOK, "POST", base+"/support-access/"+rid4+":approve", nil)
	op.must(http.StatusOK, "GET", base+"/members", nil)
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('matura.scope', 'operator', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE support_access SET expires_at = now() - interval '1 second' WHERE id = $1`, rid4)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	op.problem(http.StatusForbidden, "support-access-required", "GET", base+"/members", nil)
	states := map[string]string{}
	for _, it := range op.must(http.StatusOK, "GET", admin, nil)["items"].([]any) {
		states[it.(map[string]any)["id"].(string)] = it.(map[string]any)["state"].(string)
	}
	if states[rid] != "revoked" || states[rid2] != "denied" || states[rid3] != "ended" || states[rid4] != "expired" {
		t.Fatalf("states: %v", states)
	}

	// the tenant's setting: only owners change it; "allowed" starts access at once, "off" refuses requests
	bob.must(http.StatusForbidden, "PATCH", base, map[string]any{"support_access": "allowed"})
	alice.must(http.StatusUnprocessableEntity, "PATCH", base, map[string]any{"support_access": "always"})
	if got := alice.must(http.StatusOK, "PATCH", base, map[string]any{"support_access": "allowed"}); got["support_access"] != "allowed" {
		t.Fatalf("setting: %v", got)
	}
	if got := op.must(http.StatusCreated, "POST", admin, map[string]any{"reason": "outage", "duration_minutes": 15}); got["state"] != "active" || got["auto_approved"] != true {
		t.Fatalf("allowed without approval: %v", got)
	}
	op.must(http.StatusOK, "GET", base+"/members", nil)
	alice.must(http.StatusOK, "PATCH", base, map[string]any{"support_access": "off"})
	op.problem(http.StatusForbidden, "support-access-off", "POST", admin, map[string]any{"reason": "x", "duration_minutes": 15})
	op.must(http.StatusNotFound, "POST", "/admin/v1/tenants/"+ids.New().String()+"/support-access", map[string]any{"reason": "x", "duration_minutes": 15})
}

// TestOperatorTenantList: operators search, filter and page through tenants and read installation counts.
func TestOperatorTenantList(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	tid := map[string]string{}
	for _, slug := range []string{"acme", "acme-labs", "globex", "initech"} {
		tid[slug] = alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": slug, "name": slug})["id"].(string)
	}
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+tid["acme"]+"/members", map[string]any{"user_id": bob.user})
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+tid["acme"]+"/apps/devflow", nil)
	op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+tid["globex"]+":suspend", map[string]any{"reason": "x"})
	op.must(http.StatusAccepted, "DELETE", "/admin/v1/tenants/"+tid["initech"], nil)

	alice.must(http.StatusForbidden, "GET", "/admin/v1/tenants", nil)
	var slugs []string
	cursor := ""
	for pages := 0; ; pages++ {
		page := op.must(http.StatusOK, "GET", "/admin/v1/tenants?limit=3&cursor="+cursor, nil)
		for _, it := range page["items"].([]any) {
			m := it.(map[string]any)
			slugs = append(slugs, m["slug"].(string))
			if m["slug"] == "acme" && m["member_count"] != 2.0 {
				t.Fatalf("member count: %v", m)
			}
		}
		next, _ := page["next_cursor"].(string)
		if next == "" {
			if pages != 1 {
				t.Fatalf("%d pages", pages+1)
			}
			break
		}
		cursor = next
	}
	if len(slugs) != 4 || slugs[0] != "acme" || slugs[3] != "initech" {
		t.Fatalf("all tenants: %v", slugs)
	}
	if items := op.must(http.StatusOK, "GET", "/admin/v1/tenants?q=ACME", nil)["items"].([]any); len(items) != 2 {
		t.Fatalf("search: %v", items)
	}
	items := op.must(http.StatusOK, "GET", "/admin/v1/tenants?status=suspended,pending_deletion", nil)["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["slug"] != "globex" || items[0].(map[string]any)["status_reason"] != "x" {
		t.Fatalf("status filter: %v", items)
	}
	op.must(http.StatusUnprocessableEntity, "GET", "/admin/v1/tenants?status=gone", nil)
	op.must(http.StatusUnprocessableEntity, "GET", "/admin/v1/tenants?cursor=!!", nil)

	st := op.must(http.StatusOK, "GET", "/admin/v1/stats", nil)
	tenants, users := st["tenants"].(map[string]any), st["users"].(map[string]any)
	if tenants["active"] != 2.0 || tenants["suspended"] != 1.0 || tenants["pending_deletion"] != 1.0 || tenants["total"] != 4.0 {
		t.Fatalf("tenant stats: %v", tenants)
	}
	if users["active"] != 3.0 || users["total"] != 3.0 {
		t.Fatalf("user stats: %v", users)
	}
	apps := st["apps"].(map[string]any)
	if apps["total"] != 1.0 || apps["items"].([]any)[0].(map[string]any)["tenants"] != 1.0 {
		t.Fatalf("app stats: %v", apps)
	}
	alice.must(http.StatusForbidden, "GET", "/admin/v1/stats", nil)
}
