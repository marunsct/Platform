package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marunsct/Platform/internal/events"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
)

// appClient calls the app endpoints with HTTP Basic credentials.
type appClient struct {
	t              *testing.T
	srv            *httptest.Server
	clientID, pass string
}

func (c appClient) get(path string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.srv.URL+path, nil)
	req.SetBasicAuth(c.clientID, c.pass)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func feedTypes(items []any) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.(map[string]any)["type"].(string))
	}
	return out
}

var notesManifest = map[string]any{
	"slug": "notes", "name": "Notes",
	"auth":         map[string]any{"redirect_uris": []string{"http://localhost:9000/cb"}, "public_client": true},
	"roles":        []map[string]any{{"name": "writer", "permissions": []string{"note.write"}}},
	"default_role": "writer",
	"tenancy":      map[string]any{"modes": []string{"shared"}, "managers": []string{"app"}},
}

// TestChangeFeedIsPerApp: an app reads only tenants that enabled it and only its own grants, from a cursor.
func TestChangeFeedIsPerApp(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/secrets", map[string]any{"label": "backend"})
	if sec["secret"] == "" || sec["client_id"] != "devflow" {
		t.Fatalf("secret: %v", sec)
	}
	listed := op.must(http.StatusOK, "GET", "/admin/v1/apps/devflow/secrets", nil)["items"].([]any)
	if _, shown := listed[0].(map[string]any)["secret"]; shown {
		t.Fatal("listing shows the secret")
	}
	df := appClient{t: t, srv: srv, clientID: "devflow", pass: sec["secret"].(string)}

	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/notes", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants",
		map[string]any{"app": "devflow", "user_id": alice.user, "role": "operator"})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants",
		map[string]any{"app": "notes", "user_id": alice.user, "role": "writer"})
	globex := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	bob.must(http.StatusOK, "PUT", "/v1/tenants/"+globex["id"].(string)+"/apps/notes", nil)

	code, page := df.get("/v1/apps/devflow/changes")
	if code != http.StatusOK {
		t.Fatalf("feed: %d %v", code, page)
	}
	items := page["items"].([]any)
	types := feedTypes(items)
	for _, it := range items {
		e := it.(map[string]any)
		if tid, ok := e["tenantid"]; ok && tid != aid {
			t.Errorf("devflow sees tenant %v (%s)", tid, e["type"])
		}
		if e["type"] == "matura.grant.added" {
			if g := e["data"].(map[string]any)["grant"].(map[string]any); g["app"] != "devflow" {
				t.Errorf("devflow sees a %v grant", g["app"])
			}
		}
		if strings.HasPrefix(e["subject"].(string), "apps/notes") {
			t.Errorf("devflow sees notes' %s", e["type"])
		}
	}
	for _, want := range []string{"matura.app.manifest.updated", "matura.tenant_app.enabled", "matura.grant.added",
		"matura.placement.requested", "matura.user.created"} {
		if !strings.Contains(strings.Join(types, " "), want) {
			t.Errorf("feed lacks %s: %v", want, types)
		}
	}
	// the cursor resumes after what was read
	cursor := page["next_cursor"].(string)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "Ops"})
	_, page = df.get("/v1/apps/devflow/changes?cursor=" + cursor)
	if got := feedTypes(page["items"].([]any)); len(got) != 1 || got[0] != "matura.workspace.created" {
		t.Fatalf("after cursor: %v", got)
	}

	snap := func(q string) (int, map[string]any) { return df.get("/v1/apps/devflow/snapshot" + q) }
	if code, s := snap("?tenant=" + aid); code != http.StatusOK || len(s["memberships"].([]any)) != 1 ||
		len(s["workspaces"].([]any)) != 2 || len(s["grants"].([]any)) != 1 || s["placement"] == nil {
		t.Fatalf("snapshot of acme: %d %v", code, s)
	}
	if code, _ := snap("?tenant=" + globex["id"].(string)); code != http.StatusNotFound {
		t.Fatalf("snapshot of a tenant without devflow: %d", code)
	}
	if code, s := snap(""); code != http.StatusOK || len(s["tenants"].([]any)) != 1 || len(s["roles"].([]any)) != 2 {
		t.Fatalf("snapshot without tenant: %v", s)
	}
	if code, _ := df.get("/v1/apps/notes/changes"); code != http.StatusNotFound {
		t.Fatalf("devflow reading notes' feed: %d", code)
	}
	if code, _ := (appClient{t: t, srv: srv, clientID: "devflow", pass: "wrong"}).get("/v1/apps/devflow/changes"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", code)
	}
	if code, _ := (appClient{t: t, srv: srv, clientID: "notes", pass: df.pass}).get("/v1/apps/notes/changes"); code != http.StatusUnauthorized {
		t.Fatalf("devflow's secret with notes' client id: %d", code)
	}
	if code, _ := df.get("/v1/tenants"); code != http.StatusNotFound {
		t.Fatalf("app credentials on a user route: %d", code)
	}
	op.must(http.StatusNoContent, "DELETE", "/admin/v1/apps/devflow/secrets/"+sec["id"].(string), nil)
	if code, _ := df.get("/v1/apps/devflow/changes"); code != http.StatusUnauthorized {
		t.Fatalf("revoked secret: %d", code)
	}
}

var timeNow = time.Now

// receiver is a webhook endpoint that verifies signatures and can be told to fail.
type receiver struct {
	mu     sync.Mutex
	secret []byte
	fail   bool
	got    []events.Envelope
	bad    int
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if err := events.Verify(rc.secret, r.Header.Get("Matura-Signature"), body, timeNow()); err != nil {
		rc.bad++
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if rc.fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var e events.Envelope
	_ = json.Unmarshal(body, &e)
	rc.got = append(rc.got, e)
	w.WriteHeader(http.StatusNoContent)
}

// TestWebhooksDeliverInOrderAndCatchUp: events arrive signed and in order; a receiver that was down gets the
// missed events once it is back.
func TestWebhooksDeliverInOrderAndCatchUp(t *testing.T) {
	srv, st, keys := setupFull(t)
	store.AllowHTTPWebhooks = true
	t.Cleanup(func() { store.AllowHTTPWebhooks = false })
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)

	rc := &receiver{}
	hookSrv := httptest.NewServer(rc)
	t.Cleanup(hookSrv.Close)
	hook := op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/webhooks", map[string]any{"url": hookSrv.URL})
	rc.secret = []byte(hook["secret"].(string))
	hid := hook["id"].(string)
	op.must(http.StatusUnprocessableEntity, "POST", "/admin/v1/apps/devflow/webhooks", map[string]any{"url": "ftp://x"})

	if res := op.must(http.StatusOK, "POST", "/admin/v1/apps/devflow/webhooks/"+hid+"/test", nil); res["ok"] != true {
		t.Fatalf("test delivery: %v", res)
	}
	rc.got = nil

	relay := &events.Relay{Store: st, Keys: keys}
	alice := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/devflow", nil)
	if err := relay.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	// the tenant's earlier events become visible to the app once it is enabled, so the app learns its history
	n := len(rc.got)
	if n < 2 || rc.got[n-2].Type != "matura.tenant_app.enabled" || rc.got[n-1].Type != "matura.placement.requested" ||
		rc.got[0].Type != "matura.user.created" {
		t.Fatalf("delivered: %v", feedOf(rc.got))
	}

	// the receiver goes down: deliveries fail and back off
	rc.fail = true
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/workspaces", map[string]any{"name": "Ops"})
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/grants",
		map[string]any{"app": "devflow", "user_id": alice.user, "role": "operator"})
	_ = relay.Round(context.Background())
	hooks := op.must(http.StatusOK, "GET", "/admin/v1/apps/devflow/webhooks", nil)["items"].([]any)
	if h := hooks[0].(map[string]any); h["attempts"].(float64) != 1 || h["last_status"].(float64) != 503 {
		t.Fatalf("after failure: %v", h)
	}
	// back up; re-activating retries at once
	rc.fail = false
	op.must(http.StatusOK, "PATCH", "/admin/v1/apps/devflow/webhooks/"+hid, map[string]any{"status": "active"})
	_ = relay.Round(context.Background())
	if len(rc.got) != n+2 || rc.got[n].Type != "matura.workspace.created" || rc.got[n+1].Type != "matura.grant.added" {
		t.Fatalf("after recovery: %v", feedOf(rc.got))
	}
	if rc.bad != 0 {
		t.Fatalf("%d deliveries had bad signatures", rc.bad)
	}
	// ids are stable and sequence grows
	a, _ := strconv.Atoi(rc.got[n].Sequence)
	b, _ := strconv.Atoi(rc.got[n+1].Sequence)
	if rc.got[n].ID == rc.got[n+1].ID || a >= b {
		t.Fatalf("ids/sequence: %v", feedOf(rc.got))
	}
}

func feedOf(es []events.Envelope) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Sequence+":"+e.Type)
	}
	return out
}

func TestUsersAdminAndMyTenants(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	aid := acme["id"].(string)
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user})

	mine := bob.must(http.StatusOK, "GET", "/v1/me/tenants", nil)["items"].([]any)
	if len(mine) != 1 || mine[0].(map[string]any)["tenant_role"] != "member" {
		t.Fatalf("bob's tenants: %v", mine)
	}
	found := op.must(http.StatusOK, "GET", "/admin/v1/users?q="+bob.user.String()[24:], nil)["items"].([]any)
	if len(found) != 1 {
		t.Fatalf("search: %v", found)
	}
	alice.must(http.StatusForbidden, "GET", "/admin/v1/users", nil)

	op.must(http.StatusOK, "PATCH", "/admin/v1/users/"+bob.user.String(), map[string]any{"status": "deactivated"})
	bob.must(http.StatusForbidden, "GET", "/v1/me", nil)
	op.must(http.StatusOK, "PATCH", "/admin/v1/users/"+bob.user.String(), map[string]any{"status": "active"})
	bob.must(http.StatusOK, "GET", "/v1/me", nil)

	// a sole owner cannot be deleted; a member can, and comes back anonymised
	op.must(http.StatusUnprocessableEntity, "DELETE", "/admin/v1/users/"+alice.user.String(), nil)
	op.must(http.StatusNoContent, "DELETE", "/admin/v1/users/"+bob.user.String(), nil)
	u := op.must(http.StatusOK, "GET", "/admin/v1/users/"+bob.user.String(), nil)
	if u["status"] != "deleted" || u["email"] != nil {
		t.Fatalf("deleted user: %v", u)
	}
	bob.must(http.StatusForbidden, "GET", "/v1/me", nil) // an old token does not bring the account back
	members := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/members", nil)["items"].([]any)
	if len(members) != 1 {
		t.Fatalf("members after delete: %v", members)
	}
}
