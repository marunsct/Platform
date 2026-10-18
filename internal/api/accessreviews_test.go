package api_test

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/lifecycle"
)

// TestAccessReviews (TS11, technical specification §18.4): owners and admins review grants and tenant roles;
// completion revokes what was marked, and what nobody decided; nobody reviews their own access; the deadline
// completes a review by itself.
func TestAccessReviews(t *testing.T) {
	srv, st, _, pool := setupPool(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	dave := client{t: t, srv: srv, user: ids.New()}
	for _, c := range []client{bob, carol, dave} {
		c.must(http.StatusOK, "GET", "/v1/me", nil)
	}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	base := "/v1/tenants/" + aid
	alice.must(http.StatusOK, "PUT", base+"/apps/devflow", nil)
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": carol.user})
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": dave.user})
	grantOf := func(c client) string {
		for _, g := range alice.must(http.StatusOK, "GET", base+"/grants", nil)["items"].([]any) {
			if g := g.(map[string]any); g["subject_id"] == c.user.String() && g["status"] == "active" {
				return g["id"].(string)
			}
		}
		return ""
	}
	if grantOf(carol) == "" || grantOf(dave) == "" {
		t.Fatal("members joined without their default grant")
	}

	if code, _ := carol.do("POST", base+"/access-reviews", map[string]any{"name": "Q4", "due_at": time.Now().Add(48 * time.Hour)}); code != http.StatusForbidden {
		t.Fatalf("a member started a review: %d", code)
	}
	alice.must(http.StatusUnprocessableEntity, "POST", base+"/access-reviews", map[string]any{"name": "Q4", "due_at": time.Now()})
	rev := alice.must(http.StatusCreated, "POST", base+"/access-reviews", map[string]any{"name": "Q4 2026", "due_at": time.Now().Add(48 * time.Hour)})
	rid := rev["id"].(string)
	items := map[string]map[string]any{} // "<user>/<kind>" -> item
	for _, it := range rev["items"].([]any) {
		it := it.(map[string]any)
		items[it["user_id"].(string)+"/"+it["kind"].(string)] = it
	}
	if items[alice.user.String()+"/tenant_role"]["role"] != "owner" || items[bob.user.String()+"/tenant_role"]["role"] != "admin" ||
		items[carol.user.String()+"/grant"] == nil || items[dave.user.String()+"/grant"]["app"] != "devflow" || rev["pending"] != float64(len(items)) {
		t.Fatalf("snapshot: %v", items)
	}
	decide := func(c client, key, decision string) (int, map[string]any) {
		return c.do("PATCH", base+"/access-reviews/"+rid+"/items/"+items[key]["id"].(string), map[string]any{"decision": decision})
	}
	if code, _ := decide(bob, bob.user.String()+"/tenant_role", "keep"); code != http.StatusUnprocessableEntity {
		t.Fatalf("bob kept his own admin role: %d", code)
	}
	if code, _ := decide(bob, carol.user.String()+"/grant", "maybe"); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad decision: %d", code)
	}
	if code, it := decide(bob, carol.user.String()+"/grant", "keep"); code != 200 || it["decision"] != "keep" || it["decided_by"] != bob.user.String() {
		t.Fatalf("keep: %d %v", code, it)
	}
	if code, _ := decide(bob, dave.user.String()+"/grant", "revoke"); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	// alice (owner) is pending, so is bob's admin role: both would be revoked; alice is the last owner and stays
	done := alice.must(http.StatusOK, "POST", base+"/access-reviews/"+rid+":complete", nil)
	if done["status"] != "completed" || done["completed_by"] != alice.user.String() {
		t.Fatalf("complete: %v", done)
	}
	outcomes := map[string]string{}
	for _, it := range done["items"].([]any) {
		it := it.(map[string]any)
		outcomes[it["user_id"].(string)+"/"+it["kind"].(string)] = it["outcome"].(string)
	}
	if outcomes[dave.user.String()+"/grant"] != "revoked" || outcomes[carol.user.String()+"/grant"] != "kept" ||
		outcomes[bob.user.String()+"/tenant_role"] != "revoked" || outcomes[alice.user.String()+"/tenant_role"] != "last_owner_kept" {
		t.Fatalf("outcomes: %v", outcomes)
	}
	if grantOf(dave) != "" || grantOf(carol) == "" {
		t.Fatal("grants after the review")
	}
	for _, m := range alice.must(http.StatusOK, "GET", base+"/members", nil)["items"].([]any) {
		if m := m.(map[string]any); m["user_id"] == bob.user.String() && m["tenant_role"] != "member" {
			t.Fatalf("bob is still %v", m["tenant_role"])
		}
	}
	if code, _ := decide(alice, carol.user.String()+"/grant", "revoke"); code != http.StatusUnprocessableEntity {
		t.Fatalf("decided on a completed review: %d", code)
	}
	if code, _ := alice.do("POST", base+"/access-reviews/"+rid+":complete", nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("completed twice: %d", code)
	}

	// the deadline: a review nobody finished revokes what nobody decided (here only app grants are reviewed)
	keep := false
	late := alice.must(http.StatusCreated, "POST", base+"/access-reviews", map[string]any{"name": "devflow only",
		"due_at": time.Now().Add(2 * time.Hour), "apps": []string{"devflow"}, "tenant_roles": keep})
	for _, it := range late["items"].([]any) {
		if it.(map[string]any)["kind"] != "grant" {
			t.Fatalf("tenant roles in an apps-only review: %v", it)
		}
	}
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SELECT set_config('matura.scope', 'operator', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE access_review SET due_at = now() - interval '1 minute' WHERE id = $1`, late["id"])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&lifecycle.Purger{Store: st}).Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := alice.must(http.StatusOK, "GET", base+"/access-reviews/"+late["id"].(string), nil)
	if got["status"] != "completed" || got["completed_by"] != nil || got["revoked"] == 0.0 || grantOf(carol) != "" {
		t.Fatalf("after the deadline: %v", got)
	}
	list := alice.must(http.StatusOK, "GET", base+"/access-reviews", nil)["items"].([]any)
	if len(list) != 2 {
		t.Fatalf("reviews: %d", len(list))
	}
	actions := []string{}
	for _, e := range alice.must(http.StatusOK, "GET", base+"/audit?action=access_review", nil)["items"].([]any) {
		actions = append(actions, e.(map[string]any)["action"].(string))
	}
	if !slices.Contains(actions, "access_review.completed") || !slices.Contains(actions, "access_review.started") {
		t.Fatalf("audit: %v", actions)
	}
}
