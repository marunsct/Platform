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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/keycloak/keycloaktest"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// setupAgents is a server with the fake Keycloak admin API and maturad's protected-resource metadata.
func setupAgents(t *testing.T) (*httptest.Server, *keycloaktest.Server) {
	pool := testdb.New(t)
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	var logs io.Writer = io.Discard
	if os.Getenv("MATURA_TEST_LOG") != "" {
		logs = os.Stderr
	}
	fake := keycloaktest.New(t)
	kc, err := keycloak.New(keycloak.Config{BaseURL: fake.URL, Realm: keycloaktest.Realm,
		ClientID: keycloaktest.ClientID, ClientSecret: keycloaktest.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}
	server := api.New(store.New(pool), api.DevAuthenticator{}, keys, slog.New(slog.NewTextHandler(logs, nil)))
	server.EnableInternal(internalToken)
	server.SetKeycloak(kc, "https://id.example.test/realms/matura")
	server.SetProtectedResource("https://matura.example.test", "matura-api", "https://id.example.test/realms/matura")
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv, fake
}

var agentCanvasManifest = map[string]any{
	"slug": "agentcanvas", "name": "AgentCanvas",
	"auth": map[string]any{"redirect_uris": []string{"http://localhost:7777/cb"}, "public_client": true,
		"resources": []string{"https://canvas.example.test/mcp"}},
	"permissions": []map[string]any{{"name": "workflow.read"}, {"name": "workflow.write"}, {"name": "run.start"}},
	"roles": []map[string]any{
		{"name": "admin", "permissions": []string{"*"}},
		{"name": "editor", "permissions": []string{"workflow.read", "workflow.write", "run.start"}},
		{"name": "runner", "permissions": []string{"workflow.read", "run.start"}},
		{"name": "viewer", "permissions": []string{"workflow.read"}},
	},
	"default_role": "viewer", "owner_role": "admin",
	"tenancy": map[string]any{"modes": []string{"shared"}, "managers": []string{"app"}},
}

// TestAgents: owners and admins create service accounts and AI agents as Keycloak clients that hold grants like
// people; tokens for them carry kind and the app audience; delegated tokens carry act and only the permissions both
// sides have; deactivation stops every token at once; changes are audited with the agent as actor (TS15).
func TestAgents(t *testing.T) {
	srv, fake := setupAgents(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/agentcanvas", agentCanvasManifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	carol.must(http.StatusOK, "GET", "/v1/me", nil)
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	base := "/v1/tenants/" + aid
	alice.must(http.StatusOK, "PUT", base+"/apps/agentcanvas", nil)
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user}) // viewer

	newAgent := map[string]any{"kind": "agent", "name": "Report bot", "description": "Writes weekly reports",
		"grants": []map[string]any{{"app": "agentcanvas", "role": "runner"}}}
	bob.must(http.StatusForbidden, "POST", base+"/agents", newAgent)
	alice.must(http.StatusUnprocessableEntity, "POST", base+"/agents", map[string]any{"kind": "robot", "name": "x"})
	alice.must(http.StatusUnprocessableEntity, "POST", base+"/agents", map[string]any{"kind": "agent", "name": "x",
		"owner_id": carol.user})
	alice.must(http.StatusUnprocessableEntity, "POST", base+"/agents", map[string]any{"kind": "agent", "name": "x",
		"expires_at": time.Now().Add(-time.Hour)})
	// a grant that cannot be saved leaves no Keycloak client behind
	alice.must(http.StatusUnprocessableEntity, "POST", base+"/agents", map[string]any{"kind": "agent", "name": "x",
		"grants": []map[string]any{{"app": "agentcanvas", "role": "nope"}}})
	if fake.Lock(); len(fake.Clients) != 0 {
		fake.Unlock()
		t.Fatal("a Keycloak client was left behind after a failed save")
	}
	fake.Unlock()

	ag := alice.must(http.StatusCreated, "POST", base+"/agents", newAgent)
	agentID, clientID, secret := ag["id"].(string), ag["client_id"].(string), ag["client_secret"].(string)
	if !strings.HasPrefix(clientID, "agent-") || secret == "" || ag["owner_id"] != alice.user.String() ||
		ag["kind"] != "agent" || ag["status"] != "active" || len(ag["grants"].([]any)) != 1 ||
		ag["token_endpoint"] != "https://id.example.test/realms/matura/protocol/openid-connect/token" {
		t.Fatalf("created: %v", ag)
	}
	kc := fake.ClientByClientID(clientID)
	if kc == nil || kc["serviceAccountsEnabled"] != true || kc["publicClient"] != false ||
		kc["attributes"].(map[string]any)["standard.token.exchange.enabled"] != "true" ||
		kc["protocolMappers"].([]any)[0].(map[string]any)["protocolMapper"] != "matura-token-mapper" {
		t.Fatalf("keycloak client: %v", kc)
	}
	fake.Lock()
	if fake.ServiceUser[kc["id"].(string)] != agentID || fake.Secrets[kc["id"].(string)] != secret {
		t.Error("agent id is not the service-account user, or the secret differs")
	}
	fake.Unlock()
	if got := alice.must(http.StatusOK, "GET", base+"/agents/"+agentID, nil); got["client_secret"] != nil ||
		got["name"] != "Report bot" {
		t.Fatalf("get: %v", got)
	}
	if list := alice.must(http.StatusOK, "GET", base+"/agents", nil)["items"].([]any); len(list) != 1 ||
		len(list[0].(map[string]any)["grants"].([]any)) != 1 {
		t.Fatalf("list: %v", list)
	}
	// the agent is a user of kind agent and a member, but member endpoints are for people
	if u := op.must(http.StatusOK, "GET", "/admin/v1/users/"+agentID, nil); u["kind"] != "agent" ||
		u["display_name"] != "Report bot" {
		t.Fatalf("user: %v", u)
	}
	for _, m := range alice.must(http.StatusOK, "GET", base+"/members", nil)["items"].([]any) {
		if m.(map[string]any)["user_id"] == agentID {
			t.Fatal("the agent is listed among members")
		}
	}
	alice.must(http.StatusUnprocessableEntity, "PATCH", base+"/members/"+agentID, map[string]any{"tenant_role": "admin"})
	alice.must(http.StatusUnprocessableEntity, "DELETE", base+"/members/"+agentID, nil)
	if e := alice.must(http.StatusOK, "GET", base+"/entitlements", nil)["usage"].(map[string]any); e["agents"] != 1.0 ||
		e["members"] != 2.0 {
		t.Fatalf("usage: %v", e)
	}
	// grants for agents also go through the ordinary grant endpoint
	g := alice.must(http.StatusCreated, "POST", base+"/grants", map[string]any{"app": "agentcanvas", "user_id": agentID,
		"role": "viewer"})

	ask := func(user uuid.UUID, audience string) (int, map[string]any) {
		body := map[string]any{"user_id": user, "client_id": clientID, "audience": audience}
		if user != uuid.MustParse(agentID) {
			body["email"] = user.String()[24:] + "@example.test"
		}
		return tokenContext(t, srv.URL, internalToken, body)
	}
	agentUUID := uuid.MustParse(agentID)
	for _, aud := range []string{"", "agentcanvas", "https://canvas.example.test/mcp"} {
		code, c := ask(agentUUID, aud)
		if code != 200 || c["kind"] != "agent" || c["act"] != nil || c["aud"] != "agentcanvas" || c["tid"] != aid ||
			!slices.Equal(strs(c["perms"]), []string{"run.start", "workflow.read"}) ||
			!slices.Equal(strs(c["roles"]), []string{"runner", "viewer"}) || !slices.Equal(strs(c["troles"]), []string{"member"}) {
			t.Fatalf("agent token (audience %q): %d %v", aud, code, c)
		}
	}
	if code, c := ask(agentUUID, "billing"); code != 403 || c["error_description"] != "unknown_audience" {
		t.Fatalf("unknown audience: %d %v", code, c)
	}
	if code, c := ask(agentUUID, "matura-api"); code != 200 || c["aud"] != "matura-api" || len(c["roles"].([]any)) != 0 {
		t.Fatalf("maturad audience: %d %v", code, c)
	}
	// delegated: bob (viewer) through the agent (runner + viewer) may only read
	code, c := ask(bob.user, "")
	act, _ := c["act"].(map[string]any)
	if code != 200 || c["kind"] != "human" || act["sub"] != agentID || act["kind"] != "agent" || act["client_id"] != clientID ||
		!slices.Equal(strs(c["perms"]), []string{"workflow.read"}) || !slices.Equal(strs(c["roles"]), []string{"viewer"}) {
		t.Fatalf("delegated for bob: %d %v", code, c)
	}
	// alice is owner (implicit admin, "*"): the agent's permissions; owner and member share no tenant role
	if code, c := ask(alice.user, ""); code != 200 || !slices.Equal(strs(c["perms"]), []string{"run.start", "workflow.read"}) ||
		len(c["troles"].([]any)) != 0 {
		t.Fatalf("delegated for alice: %d %v", code, c)
	}
	if code, c := ask(carol.user, ""); code != 403 || c["error_description"] != "not_a_member" {
		t.Fatalf("delegated for an outsider: %d %v", code, c)
	}
	alice.must(http.StatusNoContent, "DELETE", base+"/grants/"+g["id"].(string), nil)

	// a delegated call to maturad's own API is audited with the agent as actor, and never manages
	viaAgent := func(user uuid.UUID, method, path string, body any) (int, map[string]any) {
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, r)
		req.Header.Set("X-Matura-Dev-User", user.String())
		req.Header.Set("X-Matura-Dev-Act", agentID)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	if code, _ := viaAgent(alice.user, "GET", base+"/workspaces", nil); code != 200 {
		t.Fatalf("delegated read: %d", code)
	}
	if code, _ := viaAgent(alice.user, "POST", base+"/workspaces", map[string]any{"name": "Agents"}); code != 403 {
		t.Fatalf("delegated manage: %d, want 403", code)
	}
	events := alice.must(http.StatusOK, "GET", base+"/audit?action=authz.denied", nil)["items"].([]any)
	if len(events) == 0 {
		t.Fatal("no authz.denied event")
	}
	actor := events[0].(map[string]any)["actor"].(map[string]any)
	if actor["kind"] != "agent" || actor["id"] != agentID || actor["on_behalf_of"] != alice.user.String() {
		t.Fatalf("audit actor: %v", actor)
	}
	if got := alice.must(http.StatusOK, "GET", base+"/audit?actor="+alice.user.String()+"&action=authz.denied", nil)["items"].([]any); len(got) == 0 {
		t.Fatal("events an agent did for alice are not found by her id")
	}
	if v := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil); v["ok"] != true {
		t.Fatalf("chain: %v", v)
	}

	// secret rotation
	rot := alice.must(http.StatusOK, "POST", base+"/agents/"+agentID+":rotate-secret", nil)
	if rot["client_secret"] == secret || rot["client_secret"] == "" || rot["version"] == ag["version"] {
		t.Fatalf("rotate: %v", rot)
	}
	alice.must(http.StatusNotFound, "POST", base+"/agents/"+agentID+":nope", nil)

	// the kill switch: deactivation refuses every token at once and disables the Keycloak client
	p := alice.must(http.StatusOK, "PATCH", base+"/agents/"+agentID, map[string]any{"status": "deactivated", "name": "Old bot"})
	if p["status"] != "deactivated" || fake.ClientByClientID(clientID)["enabled"] != false ||
		fake.ClientByClientID(clientID)["name"] != "Old bot" {
		t.Fatalf("deactivate: %v %v", p, fake.ClientByClientID(clientID))
	}
	for _, u := range []uuid.UUID{agentUUID, bob.user} {
		if code, c := ask(u, ""); code != 403 || c["error_description"] != "agent_inactive" {
			t.Fatalf("after deactivation: %d %v", code, c)
		}
	}
	if code, out := viaAgent(alice.user, "GET", base+"/workspaces", nil); code != 403 {
		t.Fatalf("delegated call after deactivation: %d %v", code, out)
	}
	if u := op.must(http.StatusOK, "GET", "/admin/v1/users/"+agentID, nil); u["status"] != "deactivated" ||
		u["display_name"] != "Old bot" {
		t.Fatalf("user after deactivation: %v", u)
	}
	alice.must(http.StatusOK, "PATCH", base+"/agents/"+agentID, map[string]any{"status": "active",
		"expires_at": time.Now().Add(1500 * time.Millisecond)})
	if code, _ := ask(agentUUID, ""); code != 200 {
		t.Fatalf("reactivated: %d", code)
	}
	time.Sleep(1600 * time.Millisecond)
	if code, c := ask(agentUUID, ""); code != 403 || c["error_description"] != "agent_expired" {
		t.Fatalf("expired: %d %v", code, c)
	}
	if e := alice.must(http.StatusOK, "PATCH", base+"/agents/"+agentID, map[string]any{"expires_at": nil}); e["expires_at"] != nil {
		t.Fatalf("clear expiry: %v", e)
	}
	ws := alice.must(http.StatusOK, "GET", base+"/audit?action=agent.", nil)["items"].([]any)
	var actions []string
	for _, e := range ws {
		actions = append(actions, e.(map[string]any)["action"].(string))
	}
	for _, want := range []string{"agent.created", "agent.secret_rotated", "agent.deactivated", "agent.reactivated", "agent.updated"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %s: %v", want, actions)
		}
	}

	// plan limit
	op.must(http.StatusOK, "PUT", "/admin/v1/plans/small", map[string]any{"name": "Small", "limits": map[string]any{"max_agents": 1}})
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+aid+"/plan", map[string]any{"plan": "small"})
	if out := alice.must(http.StatusPaymentRequired, "POST", base+"/agents", map[string]any{"kind": "service", "name": "CI"}); out["limit"] != "max_agents" {
		t.Fatalf("limit: %v", out)
	}

	// deletion removes the Keycloak client and ends the user
	alice.must(http.StatusNoContent, "DELETE", base+"/agents/"+agentID, nil)
	if fake.ClientByClientID(clientID) != nil {
		t.Fatal("Keycloak client still there")
	}
	alice.must(http.StatusNotFound, "GET", base+"/agents/"+agentID, nil)
	if list := alice.must(http.StatusOK, "GET", base+"/agents", nil)["items"].([]any); len(list) != 0 {
		t.Fatalf("list after delete: %v", list)
	}
	if u := op.must(http.StatusOK, "GET", "/admin/v1/users/"+agentID, nil); u["status"] != "deleted" {
		t.Fatalf("user after delete: %v", u)
	}
	if code, c := ask(agentUUID, ""); code != 403 || c["error_description"] != "agent_inactive" {
		t.Fatalf("token after delete: %d %v", code, c)
	}
	svc := alice.must(http.StatusCreated, "POST", base+"/agents", map[string]any{"kind": "service", "name": "CI"})
	if !strings.HasPrefix(svc["client_id"].(string), "svc-") {
		t.Fatalf("service account: %v", svc)
	}
	// other tenants cannot see the agent
	carolT := carol.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	carol.must(http.StatusNotFound, "GET", "/v1/tenants/"+carolT["id"].(string)+"/agents/"+svc["id"].(string), nil)
	carol.must(http.StatusNotFound, "GET", base+"/agents", nil)
}

// TestProtectedResourceMetadata: maturad describes its API as an OAuth protected resource (RFC 9728) and points
// 401 answers at it.
func TestProtectedResourceMetadata(t *testing.T) {
	srv, _ := setupAgents(t)
	res, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	var md map[string]any
	_ = json.NewDecoder(res.Body).Decode(&md)
	res.Body.Close()
	if res.StatusCode != 200 || md["resource"] != "https://matura.example.test" ||
		md["authorization_servers"].([]any)[0] != "https://id.example.test/realms/matura" {
		t.Fatalf("metadata: %d %v", res.StatusCode, md)
	}
	res, err = http.Get(srv.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if want := `Bearer realm="matura", resource_metadata="https://matura.example.test/.well-known/oauth-protected-resource"`; res.StatusCode != 401 || res.Header.Get("WWW-Authenticate") != want {
		t.Fatalf("401: %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	for in, want := range map[string]string{
		"https://api.example.com":         "https://api.example.com/.well-known/oauth-protected-resource",
		"https://api.example.com/mcp/":    "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		"https://api.example.com:8443/v1": "https://api.example.com:8443/.well-known/oauth-protected-resource/v1",
	} {
		if got := api.ResourceMetadataURL(in); got != want {
			t.Errorf("ResourceMetadataURL(%q) = %q, want %q", in, got, want)
		}
	}
}
