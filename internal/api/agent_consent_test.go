package api_test

import (
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/ids"
)

// TestAgentConsent (technical specification §20.5): an agent with consent required gets delegated tokens only for
// people who approved it, narrowed to what they approved; withdrawing stops it at once, tokens included.
func TestAgentConsent(t *testing.T) {
	srv, _ := setupAgents(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/agentcanvas", agentCanvasManifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	eve := client{t: t, srv: srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	eve.must(http.StatusOK, "GET", "/v1/me", nil)
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	base := "/v1/tenants/" + aid
	alice.must(http.StatusOK, "PUT", base+"/apps/agentcanvas", nil)
	alice.must(http.StatusCreated, "POST", base+"/members", map[string]any{"user_id": bob.user})
	alice.must(http.StatusCreated, "POST", base+"/grants", map[string]any{"app": "agentcanvas", "user_id": bob.user, "role": "editor"})

	alice.must(http.StatusUnprocessableEntity, "POST", base+"/agents", map[string]any{"kind": "agent", "name": "x", "consent": "maybe"})
	ag := alice.must(http.StatusCreated, "POST", base+"/agents", map[string]any{"kind": "agent", "name": "Report bot",
		"consent": "required", "grants": []map[string]any{{"app": "agentcanvas", "role": "editor"}}})
	agentID, clientID := ag["id"].(string), ag["client_id"].(string)
	if ag["consent"] != "required" {
		t.Fatalf("created: %v", ag)
	}
	ask := func(user uuid.UUID) (int, map[string]any) {
		return tokenContext(t, srv.URL, internalToken, map[string]any{"user_id": user, "client_id": clientID,
			"email": user.String()[24:] + "@example.test"})
	}
	if code, c := ask(uuid.MustParse(agentID)); code != 200 {
		t.Fatalf("the agent's own token needs no consent: %d %v", code, c)
	}
	if code, c := ask(bob.user); code != 403 || c["error_description"] != "consent_required" ||
		!strings.Contains(c["detail"].(string), "/agents/consent?client_id="+clientID) {
		t.Fatalf("without consent: %d %v", code, c)
	}

	// the consent screen's data: what the agent could do for bob (editor ∩ editor)
	req := bob.must(http.StatusOK, "GET", "/v1/me/consent-request?client_id="+clientID, nil)
	apps := req["apps"].([]any)
	if req["tenant_name"] != "Acme" || req["current"] != nil || len(apps) != 1 ||
		!slices.Equal(strs(apps[0].(map[string]any)["permissions"]), []string{"run.start", "workflow.read", "workflow.write"}) {
		t.Fatalf("consent request: %v", req)
	}
	if code, _ := eve.do("GET", "/v1/me/consent-request?client_id="+clientID, nil); code != http.StatusNotFound {
		t.Fatalf("an outsider sees the agent: %d", code)
	}
	if code, _ := eve.do("POST", "/v1/me/consents", map[string]any{"client_id": clientID}); code != http.StatusNotFound {
		t.Fatalf("an outsider consents: %d", code)
	}
	bob.must(http.StatusUnprocessableEntity, "POST", "/v1/me/consents", map[string]any{"client_id": clientID,
		"permissions": []string{"org.admin"}})
	bob.must(http.StatusUnprocessableEntity, "POST", "/v1/me/consents", map[string]any{"client_id": clientID,
		"expires_at": time.Now().Add(-time.Hour)})

	// bob allows reading only
	cons := bob.must(http.StatusCreated, "POST", "/v1/me/consents", map[string]any{"client_id": clientID,
		"permissions": []string{"workflow.read"}})
	code, c := ask(bob.user)
	if code != 200 || !slices.Equal(strs(c["perms"]), []string{"workflow.read"}) || len(strs(c["roles"])) != 0 {
		t.Fatalf("narrowed by consent: %d %v", code, c)
	}
	// widening it replaces the consent and revokes tokens got under the old one
	bob.must(http.StatusCreated, "POST", "/v1/me/consents", map[string]any{"client_id": clientID})
	if code, c := ask(bob.user); code != 200 || len(strs(c["perms"])) != 3 || len(strs(c["roles"])) != 1 {
		t.Fatalf("full consent: %d %v", code, c)
	}
	mine := bob.must(http.StatusOK, "GET", "/v1/me/consents", nil)["items"].([]any)
	if len(mine) != 1 || mine[0].(map[string]any)["agent_name"] != "Report bot" || mine[0].(map[string]any)["id"] == cons["id"] {
		t.Fatalf("my consents: %v", mine)
	}
	listed := alice.must(http.StatusOK, "GET", base+"/agents/"+agentID+"/consents", nil)["items"].([]any)
	if len(listed) != 1 || listed[0].(map[string]any)["user_id"] != bob.user.String() {
		t.Fatalf("agent consents: %v", listed)
	}
	if code, _ := bob.do("GET", base+"/agents/"+agentID+"/consents", nil); code != http.StatusForbidden {
		t.Fatalf("a member lists consents: %d", code)
	}
	later := time.Now().Add(time.Second) // a token got after the consent changed (iat is whole seconds)
	if code, _ := viaAgentAs(t, srv.URL, bob.user, agentID, aid, later).Get(base + "/workspaces"); code != 200 {
		t.Fatalf("delegated call with consent: %d", code)
	}

	// an agent cannot consent for anyone, nor withdraw
	if code, _ := viaAgentAs(t, srv.URL, bob.user, agentID, aid, later).Post("/v1/me/consents"); code != http.StatusForbidden {
		t.Fatalf("delegated consent: %d", code)
	}

	// bob withdraws: no new tokens, and the ones the agent holds for him stop at once
	id := mine[0].(map[string]any)["id"].(string)
	if code, _ := eve.do("DELETE", "/v1/me/consents/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("someone else withdraws bob's consent: %d", code)
	}
	bob.must(http.StatusNoContent, "DELETE", "/v1/me/consents/"+id, nil)
	if code, c := ask(bob.user); code != 403 || c["error_description"] != "consent_required" {
		t.Fatalf("after withdrawal: %d %v", code, c)
	}
	old := time.Now().Add(-time.Minute)
	if code, _ := viaAgentAs(t, srv.URL, bob.user, agentID, aid, old).Get(base + "/workspaces"); code != http.StatusUnauthorized {
		t.Fatalf("old delegated token after withdrawal: %d", code)
	}
	if code := tokenCall(t, bob, old, aid, "GET", base+"/workspaces"); code != http.StatusOK {
		t.Fatalf("withdrawing consent stopped bob's own token: %d", code)
	}
	if code, _ := viaAgentAs(t, srv.URL, uuid.MustParse(agentID), "", aid, old).Get(base + "/workspaces"); code == http.StatusUnauthorized {
		t.Fatal("withdrawing consent stopped the agent's own token")
	}

	// admins withdraw too
	again := bob.must(http.StatusCreated, "POST", "/v1/me/consents", map[string]any{"client_id": clientID})
	alice.must(http.StatusNotFound, "DELETE", base+"/agents/"+ids.New().String()+"/consents/"+again["id"].(string), nil)
	alice.must(http.StatusNoContent, "DELETE", base+"/agents/"+agentID+"/consents/"+again["id"].(string), nil)
	if code, _ := ask(bob.user); code != 403 {
		t.Fatalf("after an admin withdrew: %d", code)
	}

	// switching the agent to implicit consent needs none
	alice.must(http.StatusOK, "PATCH", base+"/agents/"+agentID, map[string]any{"consent": "implicit"})
	if code, c := ask(bob.user); code != 200 {
		t.Fatalf("implicit consent: %d %v", code, c)
	}
	// expiry
	alice.must(http.StatusOK, "PATCH", base+"/agents/"+agentID, map[string]any{"consent": "required"})
	bob.must(http.StatusCreated, "POST", "/v1/me/consents", map[string]any{"client_id": clientID,
		"expires_at": time.Now().Add(1200 * time.Millisecond)})
	if code, _ := ask(bob.user); code != 200 {
		t.Fatalf("before expiry: %d", code)
	}
	time.Sleep(1300 * time.Millisecond)
	if code, _ := ask(bob.user); code != 403 {
		t.Fatalf("after expiry: %d", code)
	}

	// the consent screen is served with a strict content security policy
	res, err := http.Get(srv.URL + "/agents/consent?client_id=" + clientID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") ||
		!strings.Contains(string(page), "/v1/me/consents") {
		t.Fatalf("consent page: %d %s", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
}

// devAgentCall calls maturad as user through an agent (act), with a dev token issued at iat.
type devAgentCall struct {
	t                    *testing.T
	base, user, act, tid string
	iat                  time.Time
}

func viaAgentAs(t *testing.T, base string, user uuid.UUID, act, tid string, iat time.Time) devAgentCall {
	return devAgentCall{t: t, base: base, user: user.String(), act: act, tid: tid, iat: iat}
}

func (d devAgentCall) call(method, path string) (int, string) {
	d.t.Helper()
	req, _ := http.NewRequest(method, d.base+path, strings.NewReader("{}"))
	req.Header.Set("X-Matura-Dev-User", d.user)
	if d.act != "" {
		req.Header.Set("X-Matura-Dev-Act", d.act)
	} else {
		req.Header.Set("X-Matura-Dev-Kind", "agent")
	}
	req.Header.Set("X-Matura-Dev-Tenant", d.tid)
	req.Header.Set("X-Matura-Dev-Issued-At", strconv.FormatInt(d.iat.Unix(), 10))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (d devAgentCall) Get(path string) (int, string)  { return d.call("GET", path) }
func (d devAgentCall) Post(path string) (int, string) { return d.call("POST", path) }
