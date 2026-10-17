package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/ids"
)

func tokenContext(t *testing.T, base, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+"/internal/v1/token-context", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestTokenContext: the claims Keycloak puts in a token follow memberships, grants, workspaces and the owner role,
// and are refused for non-members, disabled apps and deactivated users (technical specification §6, RL-2, RL-5).
func TestTokenContext(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	canvas := map[string]any{
		"slug": "agentcanvas", "name": "AgentCanvas",
		"auth":        map[string]any{"redirect_uris": []string{"http://localhost:7777/cb"}, "public_client": true},
		"permissions": []map[string]any{{"name": "workflow.read"}, {"name": "workflow.write"}, {"name": "run.start"}},
		"roles": []map[string]any{
			{"name": "admin", "permissions": []string{"*"}},
			{"name": "editor", "permissions": []string{"workflow.read", "workflow.write", "run.start"}},
			{"name": "viewer", "permissions": []string{"workflow.read"}},
		},
		"default_role": "viewer", "owner_role": "admin",
		"tenancy": map[string]any{"modes": []string{"shared"}, "managers": []string{"app"}},
	}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/agentcanvas", canvas)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)

	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/agentcanvas", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants",
		map[string]any{"app": "agentcanvas", "user_id": bob.user, "role": "viewer"})
	ws := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "Lab"})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants",
		map[string]any{"app": "agentcanvas", "user_id": bob.user, "role": "editor", "workspace_id": ws["id"]})
	globex := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})

	ask := func(user uuid.UUID, client, tenant, workspace string) (int, map[string]any) {
		return tokenContext(t, srv.URL, internalToken, map[string]any{"user_id": user, "email": user.String()[24:] + "@example.test",
			"client_id": client, "tenant": tenant, "workspace": workspace})
	}

	code, c := ask(alice.user, "agentcanvas", "acme", "")
	if code != 200 || c["tid"] != aid || c["tenant"] != "acme" || strs(c["troles"])[0] != "owner" ||
		strs(c["roles"])[0] != "admin" || strs(c["perms"])[0] != "*" || c["pmode"] != "shared" || c["wid"] == nil {
		t.Fatalf("owner: %d %v", code, c)
	}
	if v := c["ver"].(map[string]any); v["u"] == nil || v["m"] == nil || v["t"] == nil {
		t.Fatalf("versions: %v", v)
	}
	// bob: tenant-wide viewer; in the Lab workspace also editor
	_, c = ask(bob.user, "agentcanvas", aid, "")
	if got := strs(c["perms"]); len(got) != 1 || got[0] != "workflow.read" {
		t.Fatalf("bob in default workspace: %v", c)
	}
	_, c = ask(bob.user, "agentcanvas", "acme", ws["id"].(string))
	if got := strs(c["perms"]); len(got) != 3 || strs(c["roles"])[0] != "editor" {
		t.Fatalf("bob in Lab: %v", c)
	}
	refusals := []struct {
		user                         uuid.UUID
		client, tenant, workspace, w string
	}{
		{bob.user, "agentcanvas", "globex", "", "not_a_member"},
		{alice.user, "agentcanvas", globex["id"].(string), "", "app_not_enabled"},
		{alice.user, "devflow", "acme", "", "app_not_enabled"},
		{alice.user, "nope", "acme", "", "unknown_client"},
		{bob.user, "agentcanvas", "acme", ids.New().String(), "unknown_workspace"},
	}
	for _, rf := range refusals {
		code, c := ask(rf.user, rf.client, rf.tenant, rf.workspace)
		if code != http.StatusForbidden || c["error"] != "access_denied" || c["error_description"] != rf.w {
			t.Errorf("%s/%s/%s: %d %v, want %s", rf.client, rf.tenant, rf.workspace, code, c, rf.w)
		}
	}
	// no tenant named: the last one used; alice used globex last (refused, but chosen), so name acme again first
	ask(alice.user, "agentcanvas", "acme", "")
	if _, c := ask(alice.user, "agentcanvas", "", ""); c["tenant"] != "acme" {
		t.Fatalf("last used: %v", c)
	}
	// a brand-new user with no tenant gets a token without tid, for onboarding
	if code, c := ask(ids.New(), "agentcanvas", "", ""); code != 200 || c["tid"] != nil || len(c["roles"].([]any)) != 0 {
		t.Fatalf("new user: %d %v", code, c)
	}
	op.must(http.StatusOK, "PATCH", "/admin/v1/users/"+bob.user.String(), map[string]any{"status": "deactivated"})
	if code, c := ask(bob.user, "agentcanvas", "acme", ""); code != http.StatusForbidden || c["error_description"] != "user_inactive" {
		t.Fatalf("deactivated: %d %v", code, c)
	}
	if code, _ := tokenContext(t, srv.URL, "wrong", map[string]any{"user_id": alice.user, "client_id": "agentcanvas"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong internal token: %d", code)
	}
}
