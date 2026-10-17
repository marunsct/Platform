package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	user uuid.UUID
	op   bool
	name string // X-Matura-Dev-Name, when set
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
		if c.name != "" {
			req.Header.Set("X-Matura-Dev-Name", c.name)
		}
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

const internalToken = "internal-test-token-0123456789abcdef"

func setup(t *testing.T) *httptest.Server {
	srv, _, _ := setupFull(t)
	return srv
}

// setupFull also returns the store and keys, for tests that run the relay or the provisioner.
func setupFull(t *testing.T) (*httptest.Server, *store.Store, secrets.KeyManager) {
	srv, st, keys, _ := setupPool(t)
	return srv, st, keys
}

// setupPool also returns the runtime role's pool, for tests that change rows directly (say, to expire them).
func setupPool(t *testing.T) (*httptest.Server, *store.Store, secrets.KeyManager, *pgxpool.Pool) {
	pool := testdb.New(t)
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	var logs io.Writer = io.Discard
	if os.Getenv("MATURA_TEST_LOG") != "" {
		logs = os.Stderr
	}
	server := api.New(st, api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(logs, nil)))
	server.EnableInternal(internalToken)
	server.SetInvitations(api.Invitations{PublicURL: "http://matura.test", Issuer: "http://keycloak.test/realms/matura",
		ClientID: "matura-console"})
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv, st, keys, pool
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
	inv := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/invitations",
		map[string]any{"email": "carol@example.test"})
	iid := inv["id"].(string)
	sink := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/audit/sinks",
		map[string]any{"url": "https://siem.example.test/in"})
	sid := sink["id"].(string)

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
		{"GET", "/v1/tenants/" + aid + "/invitations", nil},
		{"POST", "/v1/tenants/" + aid + "/invitations", map[string]any{"email": "x@example.test"}},
		{"POST", "/v1/tenants/" + aid + "/invitations/" + iid + ":resend", nil},
		{"DELETE", "/v1/tenants/" + aid + "/invitations/" + iid, nil},
		{"GET", "/v1/tenants/" + aid + "/audit", nil},
		{"GET", "/v1/tenants/" + aid + "/audit/export", nil},
		{"GET", "/v1/tenants/" + aid + "/audit:verify", nil},
		{"GET", "/v1/tenants/" + aid + "/audit/sinks", nil},
		{"POST", "/v1/tenants/" + aid + "/audit/sinks", map[string]any{"url": "https://x.example.test"}},
		{"PATCH", "/v1/tenants/" + aid + "/audit/sinks/" + sid, map[string]any{"status": "disabled"}},
		{"DELETE", "/v1/tenants/" + aid + "/audit/sinks/" + sid, nil},
		{"GET", "/v1/tenants/" + aid + "/security-policy", nil},
		{"PUT", "/v1/tenants/" + aid + "/security-policy", map[string]any{"require_mfa": true}},
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

// TestRolesManagedInPlatform covers RL-8 to RL-11: roles are created, renamed, edited and deleted in Matura, and a
// re-applied manifest leaves those changes alone.
func TestRolesManagedInPlatform(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	m := map[string]any{
		"slug": "devflow", "name": "DevFlow",
		"auth":        map[string]any{"redirect_uris": []string{"http://localhost:8000/cb"}},
		"permissions": []map[string]any{{"name": "run.read"}, {"name": "run.start"}, {"name": "run.cancel"}},
		"roles": []map[string]any{
			{"name": "operator", "permissions": []string{"run.read", "run.start"}},
			{"name": "viewer", "permissions": []string{"run.read"}},
		},
		"default_role": "viewer",
	}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", m)

	// a role defined in Matura, from the catalogue only
	op.must(http.StatusUnprocessableEntity, "POST", "/admin/v1/apps/devflow/roles",
		map[string]any{"name": "auditor", "permissions": []string{"billing.read"}})
	op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/roles",
		map[string]any{"name": "auditor", "permissions": []string{"run.read"}})
	// non-operators cannot
	owner := client{t: t, srv: srv, user: ids.New()}
	owner.must(http.StatusForbidden, "POST", "/admin/v1/apps/devflow/roles",
		map[string]any{"name": "x", "permissions": []string{"run.read"}})

	// grant it, then rename it: the grant follows
	acme := owner.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	tid := acme["id"].(string)
	owner.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/devflow", nil)
	owner.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/grants",
		map[string]any{"app": "devflow", "user_id": owner.user, "role": "auditor"})
	op.must(http.StatusOK, "PATCH", "/admin/v1/apps/devflow/roles/auditor", map[string]any{"name": "reviewer"})
	grants := owner.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/grants", nil)["items"].([]any)
	if len(grants) != 1 || grants[0].(map[string]any)["role"] != "reviewer" {
		t.Fatalf("grant after rename: %v", grants)
	}

	// edit a starter role; re-applying the manifest must not undo it
	op.must(http.StatusOK, "PATCH", "/admin/v1/apps/devflow/roles/operator",
		map[string]any{"permissions": []string{"run.read", "run.start", "run.cancel"}})
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", m)
	roles := op.must(http.StatusOK, "GET", "/v1/apps/devflow/roles", nil)["items"].([]any)
	got := map[string]map[string]any{}
	for _, r := range roles {
		got[r.(map[string]any)["name"].(string)] = r.(map[string]any)
	}
	if p := got["operator"]["permissions"].([]any); len(p) != 3 || got["operator"]["edited"] != true {
		t.Fatalf("edited role after re-apply: %v", got["operator"])
	}
	if got["reviewer"]["origin"] != "platform" || got["viewer"]["is_default"] != true {
		t.Fatalf("roles after re-apply: %v", got)
	}

	// a manifest may not drop a permission a role still uses
	m["permissions"] = []map[string]any{{"name": "run.read"}, {"name": "run.start"}}
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/apps/devflow", m)

	// a held role and the default role cannot be deleted; a free one can
	op.must(http.StatusUnprocessableEntity, "DELETE", "/admin/v1/apps/devflow/roles/reviewer", nil)
	op.must(http.StatusUnprocessableEntity, "DELETE", "/admin/v1/apps/devflow/roles/viewer", nil)
	op.must(http.StatusOK, "PATCH", "/admin/v1/apps/devflow/roles/operator", map[string]any{"is_default": true})
	op.must(http.StatusNoContent, "DELETE", "/admin/v1/apps/devflow/roles/viewer", nil)
}
