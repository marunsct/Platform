package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/marunsct/Platform/internal/ids"
)

func TestPlans(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/plans/enterprise",
		map[string]any{"name": "Enterprise", "data_mode_required": "database", "limits": map[string]any{"seats": 500}})
	op.must(http.StatusOK, "PUT", "/admin/v1/plans/enterprise", map[string]any{"name": "Enterprise 2"})
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/plans/Bad%20Id", map[string]any{})
	var found map[string]any
	for _, p := range op.must(http.StatusOK, "GET", "/admin/v1/plans", nil)["items"].([]any) {
		if p.(map[string]any)["id"] == "enterprise" {
			found = p.(map[string]any)
		}
	}
	if found == nil || found["name"] != "Enterprise 2" || found["data_mode_required"] != nil {
		t.Fatalf("plan after replace: %v", found)
	}
	user := client{t: t, srv: srv, user: ids.New()}
	user.must(http.StatusForbidden, "GET", "/admin/v1/plans", nil)
}

// TestDBServers registers the test Postgres itself as a database server: the password is sealed and never returned,
// the connection test opens it again, and rotation changes the fingerprint.
func TestDBServers(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	u, err := url.Parse(os.Getenv("MATURA_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	created := op.must(http.StatusCreated, "POST", "/admin/v1/db-servers", map[string]any{
		"name": "pg-test", "host": u.Hostname(), "port": port, "admin_user": u.User.Username(),
		"admin_password": "s3cret-value", "sslmode": "disable"})
	id := created["id"].(string)
	if _, leaked := created["admin_password"]; leaked || created["admin_secret_fingerprint"] == "" {
		t.Fatalf("create response: %v", created)
	}
	list, _ := json.Marshal(op.must(http.StatusOK, "GET", "/admin/v1/db-servers", nil))
	if bytes.Contains(list, []byte("s3cret-value")) {
		t.Fatal("list returns the admin password")
	}
	check := op.must(http.StatusOK, "POST", "/admin/v1/db-servers/"+id+"/test", nil)
	if check["ok"] != true || check["server_version"] == "" {
		t.Fatalf("connection test: %v", check)
	}
	rotated := op.must(http.StatusOK, "PATCH", "/admin/v1/db-servers/"+id,
		map[string]any{"admin_password": "another", "status": "draining"})
	if rotated["admin_secret_fingerprint"] == created["admin_secret_fingerprint"] || rotated["status"] != "draining" {
		t.Fatalf("after rotation: %v", rotated)
	}
	op.must(http.StatusUnprocessableEntity, "PATCH", "/admin/v1/db-servers/"+id, map[string]any{"status": "gone"})
	op.must(http.StatusUnprocessableEntity, "POST", "/admin/v1/db-servers",
		map[string]any{"name": "x", "host": "h", "admin_user": "u"})
	op.must(http.StatusNoContent, "DELETE", "/admin/v1/db-servers/"+id, nil)
	op.must(http.StatusNotFound, "DELETE", "/admin/v1/db-servers/"+id, nil)
}

func TestIdempotencyKey(t *testing.T) {
	srv := setup(t)
	user := ids.New()
	post := func(key, body string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/tenants", strings.NewReader(body))
		req.Header.Set("X-Matura-Dev-User", user.String())
		req.Header.Set("X-Matura-Dev-Email", user.String()[24:]+"@example.test")
		req.Header.Set("Idempotency-Key", key)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}
	body := `{"slug":"initech","name":"Initech"}`
	first, a := post("k1", body)
	again, b := post("k1", body)
	if first.StatusCode != http.StatusCreated || again.StatusCode != http.StatusCreated || a["id"] != b["id"] {
		t.Fatalf("retry: %d %v, then %d %v", first.StatusCode, a, again.StatusCode, b)
	}
	if again.Header.Get("Idempotency-Replayed") != "true" || first.Header.Get("Idempotency-Replayed") != "" {
		t.Fatal("Idempotency-Replayed header is wrong")
	}
	if res, _ := post("k1", `{"slug":"other","name":"Other"}`); res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("same key, different body: %d, want 422", res.StatusCode)
	}
	// a conflict is a client error, so it is stored and replayed too
	if res, _ := post("k2", body); res.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate slug with a new key: %d, want 409", res.StatusCode)
	}
}
