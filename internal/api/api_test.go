package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	user uuid.UUID
	op   bool
}

func (c client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, r)
	if c.user != uuid.Nil {
		req.Header.Set("X-Matura-Dev-User", c.user.String())
		req.Header.Set("X-Matura-Dev-Email", c.user.String()[24:]+"@example.test")
	}
	if c.op {
		req.Header.Set("X-Matura-Dev-Operator", "true")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (c client) must(want int, method, path string, body any) map[string]any {
	c.t.Helper()
	got, out := c.do(method, path, body)
	if got != want {
		c.t.Fatalf("%s %s: status %d, want %d (%v)", method, path, got, want, out)
	}
	return out
}

func setup(t *testing.T) *httptest.Server {
	pool := testdb.New(t)
	srv := httptest.NewServer(api.New(store.New(pool), api.DevAuthenticator{},
		slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return srv
}

var manifest = map[string]any{
	"slug": "devflow", "name": "DevFlow",
	"auth":         map[string]any{"redirect_uris": []string{"http://localhost:8000/cb"}, "public_client": true},
	"roles":        []map[string]any{{"name": "admin", "permissions": []string{"*"}}, {"name": "operator", "permissions": []string{"run.start"}}},
	"default_role": "operator",
	"tenancy":      map[string]any{"modes": []string{"shared", "database"}, "managers": []string{"platform"}},
}

func TestNeedsSignIn(t *testing.T) {
	srv := setup(t)
	c := client{t: t, srv: srv}
	c.must(http.StatusUnauthorized, "GET", "/v1/tenants", nil)
	c.must(http.StatusNoContent, "GET", "/healthz/live", nil)
	c.must(http.StatusNoContent, "GET", "/healthz/ready", nil)
	user := client{t: t, srv: srv, user: ids.New()}
	user.must(http.StatusForbidden, "PUT", "/admin/v1/apps/devflow", manifest)
}

// TestCrossTenant calls every tenant route as a member of globex with acme's ids: all must answer 404 (TN-4).
func TestCrossTenant(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)

	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	aid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	ws := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/workspaces", nil)["items"].([]any)
	wid := ws[0].(map[string]any)["id"].(string)
	grant := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants",
		map[string]any{"app": "devflow", "user_id": alice.user, "role": "admin"})
	gid := grant["id"].(string)

	routes := []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/tenants/" + aid, nil},
		{"PATCH", "/v1/tenants/" + aid, map[string]any{"name": "x"}},
		{"DELETE", "/v1/tenants/" + aid, nil},
		{"GET", "/v1/tenants/" + aid + "/workspaces", nil},
		{"POST", "/v1/tenants/" + aid + "/workspaces", map[string]any{"name": "x"}},
		{"PATCH", "/v1/tenants/" + aid + "/workspaces/" + wid, map[string]any{"name": "x"}},
		{"GET", "/v1/tenants/" + aid + "/members", nil},
		{"POST", "/v1/tenants/" + aid + "/members", map[string]any{"user_id": bob.user}},
		{"PATCH", "/v1/tenants/" + aid + "/members/" + alice.user.String(), map[string]any{"tenant_role": "member"}},
		{"DELETE", "/v1/tenants/" + aid + "/members/" + alice.user.String(), nil},
		{"GET", "/v1/tenants/" + aid + "/apps", nil},
		{"PUT", "/v1/tenants/" + aid + "/apps/devflow", nil},
		{"DELETE", "/v1/tenants/" + aid + "/apps/devflow", nil},
		{"GET", "/v1/tenants/" + aid + "/grants", nil},
		{"POST", "/v1/tenants/" + aid + "/grants", map[string]any{"app": "devflow", "user_id": bob.user, "role": "admin"}},
		{"DELETE", "/v1/tenants/" + aid + "/grants/" + gid, nil},
	}
	for _, rt := range routes {
		if got, out := bob.do(rt.method, rt.path, rt.body); got != http.StatusNotFound {
			t.Errorf("%s %s as another tenant: %d, want 404 (%v)", rt.method, rt.path, got, out)
		}
	}
	// and acme is untouched
	got := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid, nil)
	if got["name"] != "Acme" || got["status"] != "active" {
		t.Fatalf("acme changed: %v", got)
	}
	list := bob.must(http.StatusOK, "GET", "/v1/tenants", nil)["items"].([]any)
	if len(list) != 1 {
		t.Fatalf("bob lists %d tenants, want 1", len(list))
	}
}

func TestRolesInsideATenant(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)

	owner := client{t: t, srv: srv, user: ids.New()}
	admin := client{t: t, srv: srv, user: ids.New()}
	member := client{t: t, srv: srv, user: ids.New()}
	acme := owner.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	tid := acme["id"].(string)
	// people need an account before they can be added (invitations come in TS6)
	admin.must(http.StatusOK, "GET", "/v1/me", nil)
	member.must(http.StatusOK, "GET", "/v1/me", nil)
	owner.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/members", map[string]any{"user_id": admin.user, "tenant_role": "admin"})
	owner.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/members", map[string]any{"user_id": member.user})

	// members read but do not manage
	member.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/members", nil)
	member.must(http.StatusForbidden, "POST", "/v1/tenants/"+tid+"/workspaces", map[string]any{"name": "x"})
	member.must(http.StatusForbidden, "PUT", "/v1/tenants/"+tid+"/apps/devflow", nil)

	// admins manage, but only owners make owners or touch them
	admin.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/devflow", nil)
	admin.must(http.StatusForbidden, "PATCH", "/v1/tenants/"+tid+"/members/"+member.user.String(), map[string]any{"tenant_role": "owner"})
	admin.must(http.StatusForbidden, "DELETE", "/v1/tenants/"+tid+"/members/"+owner.user.String(), nil)
	admin.must(http.StatusForbidden, "DELETE", "/v1/tenants/"+tid, nil)
	admin.must(http.StatusForbidden, "PATCH", "/v1/tenants/"+tid, map[string]any{"plan": "enterprise"})
	admin.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/grants", map[string]any{"app": "devflow", "user_id": member.user, "role": "operator"})

	// the last owner cannot leave
	got, out := owner.do("DELETE", "/v1/tenants/"+tid+"/members/"+owner.user.String(), nil)
	if got != http.StatusUnprocessableEntity || !strings.Contains(out["detail"].(string), "owner") {
		t.Fatalf("last owner leaving: %d %v", got, out)
	}
	// a member may leave
	member.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+tid+"/members/"+member.user.String(), nil)
	member.must(http.StatusNotFound, "GET", "/v1/tenants/"+tid, nil)

	// stale If-Match
	cur := owner.must(http.StatusOK, "GET", "/v1/tenants/"+tid, nil)
	req, _ := http.NewRequest("PATCH", srv.URL+"/v1/tenants/"+tid, strings.NewReader(`{"name":"Acme 2"}`))
	req.Header.Set("X-Matura-Dev-User", owner.user.String())
	req.Header.Set("If-Match", `"1"`)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match (current version %v): %d", cur["version"], res.StatusCode)
	}
}
