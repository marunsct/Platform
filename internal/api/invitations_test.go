package api_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/mail"
)

// fakeSender keeps what the mailer sends.
type fakeSender struct {
	mu   sync.Mutex
	sent []sentMail
}

type sentMail struct{ to, subject, body string }

func (f *fakeSender) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMail{to, subject, body})
	return nil
}

var canvasManifest = map[string]any{
	"slug": "agentcanvas", "name": "AgentCanvas",
	"auth":         map[string]any{"redirect_uris": []string{"http://localhost:7777/cb"}, "public_client": true},
	"roles":        []map[string]any{{"name": "admin", "permissions": []string{"*"}}, {"name": "viewer", "permissions": []string{"canvas.read"}}},
	"default_role": "viewer",
	"tenancy":      map[string]any{"modes": []string{"shared"}, "managers": []string{"platform"}},
}

func emailOf(c client) string { return c.user.String()[24:] + "@example.test" }

func tokenOf(t *testing.T, acceptURL string) string {
	t.Helper()
	u, err := url.Parse(acceptURL)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("accept url %q has no token", acceptURL)
	}
	return u.Query().Get("token")
}

// rolesOf returns the user's active grants in the tenant as app -> role.
func rolesOf(c client, tid, uid string) map[string]string {
	out := map[string]string{}
	for _, g := range c.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/grants", nil)["items"].([]any) {
		g := g.(map[string]any)
		if g["subject_id"] == uid && g["status"] == "active" {
			out[g["app"].(string)] = g["role"].(string)
		}
	}
	return out
}

// TestInvitations covers UM-1, UM-2 and RL-4: an invited user accepts and lands in the tenant with the invitation's
// tenant role and app roles, plus the default role of every other enabled app; spent, revoked, expired and
// misdirected links are refused.
func TestInvitations(t *testing.T) {
	srv, st, _, pool := setupPool(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/agentcanvas", canvasManifest)

	owner := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	acme := owner.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	tid := acme["id"].(string)
	owner.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/devflow", nil)
	owner.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/agentcanvas", nil)
	base := "/v1/tenants/" + tid + "/invitations"

	// refused up front: a role the app does not have, an app not enabled, a delivery not built yet
	owner.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"email": emailOf(bob),
		"app_roles": []map[string]any{{"app": "devflow", "role": "wizard"}}})
	owner.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"email": emailOf(bob),
		"app_roles": []map[string]any{{"app": "nope", "role": "admin"}}})
	// temporary passwords need Keycloak's admin API (TestTemporaryPasswordOnboarding has it)
	owner.must(http.StatusServiceUnavailable, "POST", base, map[string]any{"email": emailOf(bob),
		"delivery": "temp_password"})
	owner.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"email": emailOf(bob), "delivery": "pigeon"})
	owner.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"email": "not-an-address"})

	inv := owner.must(http.StatusCreated, "POST", base, map[string]any{"email": strings.ToUpper(emailOf(bob)),
		"tenant_role": "admin", "app_roles": []map[string]any{{"app": "devflow", "role": "admin"}}})
	if inv["state"] != "pending" || inv["tenant_role"] != "admin" {
		t.Fatalf("invitation: %v", inv)
	}
	acceptURL := inv["accept_url"].(string)
	if !strings.HasPrefix(acceptURL, "http://matura.test/invitations/accept?token=") {
		t.Fatalf("accept url %q", acceptURL)
	}
	token := tokenOf(t, acceptURL)

	// the email is queued with the invitation and sent by the mailer
	sender := &fakeSender{}
	mailer := &mail.Mailer{Store: st, Sender: sender}
	if n, err := mailer.Round(context.Background()); err != nil || n != 1 {
		t.Fatalf("mailer sent %d (%v), want 1", n, err)
	}
	if got := sender.sent[0]; !strings.EqualFold(got.to, emailOf(bob)) || !strings.Contains(got.body, acceptURL) ||
		!strings.Contains(got.subject, "Acme") {
		t.Fatalf("email: %+v", got)
	}
	if n, _ := mailer.Round(context.Background()); n != 0 {
		t.Fatalf("mailer sent %d again", n)
	}

	// the link's page and its preview work without signing in; the token is the credential
	anon := client{t: t, srv: srv}
	pv := anon.must(http.StatusOK, "GET", "/invitations/preview?token="+url.QueryEscape(token), nil)
	if pv["tenant_name"] != "Acme" || pv["state"] != "pending" {
		t.Fatalf("preview: %v", pv)
	}
	anon.must(http.StatusGone, "GET", "/invitations/preview?token=wrong", nil)
	res, err := http.Get(srv.URL + "/invitations/accept?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(page), `"client_id":"matura-console"`) ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "connect-src 'self' http://keycloak.test") {
		t.Fatalf("accept page: %d %s", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}

	// only the invited address may accept
	carol.must(http.StatusForbidden, "POST", "/v1/invitations:accept", map[string]any{"token": token})
	carol.must(http.StatusGone, "POST", "/v1/invitations:accept", map[string]any{"token": "made-up"})

	out := bob.must(http.StatusOK, "POST", "/v1/invitations:accept", map[string]any{"token": token})
	if m := out["membership"].(map[string]any); m["tenant_role"] != "admin" || m["status"] != "active" {
		t.Fatalf("membership: %v", m)
	}
	// devflow: the invitation's role instead of the default; agentcanvas: its default role (RL-4)
	roles := rolesOf(owner, tid, bob.user.String())
	if len(roles) != 2 || roles["devflow"] != "admin" || roles["agentcanvas"] != "viewer" {
		t.Fatalf("bob's roles: %v", roles)
	}
	bob.must(http.StatusGone, "POST", "/v1/invitations:accept", map[string]any{"token": token}) // single use
	if pv := anon.must(http.StatusOK, "GET", "/invitations/preview?token="+url.QueryEscape(token), nil); pv["state"] != "accepted" {
		t.Fatalf("preview after accepting: %v", pv)
	}
	owner.must(http.StatusConflict, "POST", base, map[string]any{"email": emailOf(bob)})

	// members added directly get default roles too (RL-4)
	dave := client{t: t, srv: srv, user: ids.New()}
	dave.must(http.StatusOK, "GET", "/v1/me", nil)
	owner.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/members", map[string]any{"user_id": dave.user})
	if roles := rolesOf(owner, tid, dave.user.String()); roles["devflow"] != "operator" || roles["agentcanvas"] != "viewer" {
		t.Fatalf("dave's roles: %v", roles)
	}

	// resend: the old link stops working, the new one works
	carolInv := owner.must(http.StatusCreated, "POST", base, map[string]any{"email": emailOf(carol)})
	cid := carolInv["id"].(string)
	oldToken := tokenOf(t, carolInv["accept_url"].(string))
	resent := owner.must(http.StatusOK, "POST", base+"/"+cid+":resend", nil)
	if resent["sent_count"].(float64) != 2 {
		t.Fatalf("resent: %v", resent)
	}
	carol.must(http.StatusGone, "POST", "/v1/invitations:accept", map[string]any{"token": oldToken})

	// an expired link is refused, with the message the accept page shows
	newToken := tokenOf(t, resent["accept_url"].(string))
	expire(t, pool, cid)
	list := owner.must(http.StatusOK, "GET", base, nil)["items"].([]any)
	for _, it := range list {
		if it := it.(map[string]any); it["id"] == cid && it["state"] != "expired" {
			t.Fatalf("listed as %v, want expired", it["state"])
		}
	}
	_, gone := carol.do("POST", "/v1/invitations:accept", map[string]any{"token": newToken})
	if !strings.Contains(gone["detail"].(string), "ask your admin for a new invitation") {
		t.Fatalf("expired: %v", gone)
	}
	// resending an expired invitation brings it back; revoking it ends it
	again := owner.must(http.StatusOK, "POST", base+"/"+cid+":resend", nil)
	owner.must(http.StatusNoContent, "DELETE", base+"/"+cid, nil)
	carol.must(http.StatusGone, "POST", "/v1/invitations:accept", map[string]any{"token": tokenOf(t, again["accept_url"].(string))})

	// a new invitation to the same address replaces the pending one
	first := owner.must(http.StatusCreated, "POST", base, map[string]any{"email": emailOf(carol)})
	second := owner.must(http.StatusCreated, "POST", base, map[string]any{"email": emailOf(carol)})
	carol.must(http.StatusGone, "POST", "/v1/invitations:accept", map[string]any{"token": tokenOf(t, first["accept_url"].(string))})
	carol.must(http.StatusOK, "POST", "/v1/invitations:accept", map[string]any{"token": tokenOf(t, second["accept_url"].(string))})

	// only owners invite owners; members cannot invite at all
	bob.must(http.StatusForbidden, "POST", base, map[string]any{"email": "x@example.test", "tenant_role": "owner"})
	carol.must(http.StatusForbidden, "POST", base, map[string]any{"email": "x@example.test"})
	carol.must(http.StatusForbidden, "GET", base, nil)
}

func expire(t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, id string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT set_config('matura.scope', 'operator', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE invitation SET expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
