package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/lifecycle"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// fakeTransit is an OpenBao transit endpoint that a tenant can revoke (it then answers 403).
type fakeTransit struct {
	key     *secrets.Local
	revoked atomic.Bool
	srv     *httptest.Server
}

func newFakeTransit(t *testing.T) *fakeTransit {
	k, _ := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)))
	f := &fakeTransit{key: k}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.revoked.Load() || r.Header.Get("X-Vault-Token") != "tenant-token" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		aad, _ := base64.StdEncoding.DecodeString(in["associated_data"])
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/encrypt/acme-key"):
			p, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			ct, _ := f.key.Wrap(context.Background(), p, aad)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct)}})
		case strings.HasSuffix(r.URL.Path, "/decrypt/acme-key"):
			ct, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(in["ciphertext"], "vault:v1:"))
			p, err := f.key.Unwrap(context.Background(), ct, aad)
			if err != nil {
				http.Error(w, `{"errors":["bad ciphertext"]}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(p)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func setupKeys(t *testing.T) (*httptest.Server, *store.Store, *secrets.Ring, *pgxpool.Pool) {
	pool := testdb.New(t)
	local, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ring := secrets.NewRing(local)
	st := store.New(pool)
	var logs io.Writer = io.Discard
	if os.Getenv("MATURA_TEST_LOG") != "" {
		logs = os.Stderr
	}
	server := api.New(st, api.DevAuthenticator{}, ring, slog.New(slog.NewTextHandler(logs, nil)))
	server.EnableTenantKeysTTL(ring, &secrets.CustomerKeys{Providers: []string{"transit"}, AllowHTTP: true}, 150*time.Millisecond)
	server.SetDeletionGrace(0)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv, st, ring, pool
}

// asOperator runs one query in operator scope, as row-level security requires.
func asOperator(t *testing.T, pool *pgxpool.Pool, sql string, args []any, dest ...any) {
	t.Helper()
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SELECT set_config('matura.scope', 'operator', true)`); err != nil {
			return err
		}
		return tx.QueryRow(context.Background(), sql, args...).Scan(dest...)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (c appClient) post(path string, body any) (int, map[string]any) {
	c.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.srv.URL+path, bytes.NewReader(b))
	req.SetBasicAuth(c.clientID, c.pass)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// TestTenantKeysAndCryptoShredding (TS17, technical specification §9.2): apps get data keys sealed under the
// tenant key; tenant secrets are sealed under it; a tenant's own key seals its keys and revoking it makes them
// unreadable; deleting the tenant destroys its keys for good.
func TestTenantKeysAndCryptoShredding(t *testing.T) {
	srv, st, ring, pool := setupKeys(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/secrets", map[string]any{"label": "b"})
	notes := appClient{t: t, srv: srv, clientID: "notes", pass: sec["secret"].(string)}
	dsec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/secrets", map[string]any{"label": "b"})
	devflow := appClient{t: t, srv: srv, clientID: "devflow", pass: dsec["secret"].(string)}

	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	bid := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/apps/notes", nil)
	bob.must(http.StatusOK, "PUT", "/v1/tenants/"+bid+"/apps/notes", nil)

	// data keys for field encryption
	code, dk := notes.post("/v1/apps/notes/tenants/"+aid+"/data-keys", nil)
	if code != http.StatusCreated || dk["key_version"] != 1.0 {
		t.Fatalf("data key: %d %v", code, dk)
	}
	plain, _ := base64.StdEncoding.DecodeString(dk["plaintext"].(string))
	if len(plain) != 32 {
		t.Fatalf("data key length %d", len(plain))
	}
	unwrap := func(a appClient, tid string, wrapped any) (int, map[string]any) {
		return a.post("/v1/apps/"+a.clientID+"/tenants/"+tid+"/data-keys:unwrap", map[string]any{"wrapped": wrapped})
	}
	if code, out := unwrap(notes, aid, dk["wrapped"]); code != 200 || out["plaintext"] != dk["plaintext"] {
		t.Fatalf("unwrap: %d %v", code, out)
	}
	if code, _ := unwrap(notes, bid, dk["wrapped"]); code != http.StatusUnprocessableEntity {
		t.Fatalf("another tenant's data key unwrapped: %d", code)
	}
	if code, _ := unwrap(devflow, aid, dk["wrapped"]); code != http.StatusNotFound {
		t.Fatalf("an app the tenant did not enable unwraps: %d", code)
	}
	if code, _ := devflow.post("/v1/apps/devflow/tenants/"+aid+"/data-keys", nil); code != http.StatusNotFound {
		t.Fatalf("data key for a tenant without the app: %d", code)
	}
	bad, _ := base64.StdEncoding.DecodeString(dk["wrapped"].(string))
	bad[len(bad)-1] ^= 1
	if code, _ := unwrap(notes, aid, bad); code != http.StatusUnprocessableEntity {
		t.Fatalf("a changed data key unwrapped: %d", code)
	}

	// tenant secrets are sealed under the tenant key
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/audit/sinks", map[string]any{"url": "https://siem.example.test/hook"})
	var sinkID string
	var sinkSecret []byte
	asOperator(t, pool, `SELECT id::text, secret FROM audit_sink WHERE tenant_id = $1`, []any{aid}, &sinkID, &sinkSecret)
	if tid, _, ok := store.TenantOf(sinkSecret); !ok || tid.String() != aid {
		t.Fatalf("audit sink secret not sealed under the tenant key (format %d)", sinkSecret[0])
	}
	if _, err := ring.Open(sinkSecret, "audit_sink:"+sinkID); err != nil {
		t.Fatalf("the ring does not open a tenant-sealed secret: %v", err)
	}

	// owners see and rotate keys; admins cannot
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/members", map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	if code, _ := bob.do("GET", "/v1/tenants/"+aid+"/keys", nil); code != http.StatusForbidden {
		t.Fatalf("an admin sees keys: %d", code)
	}
	info := alice.must(http.StatusOK, "GET", "/v1/tenants/"+aid+"/keys", nil)
	if v := info["versions"].([]any); len(v) != 1 || v[0].(map[string]any)["sealed_by"] != "installation" || info["provider"] != nil {
		t.Fatalf("keys: %v", info)
	}
	if got := alice.must(http.StatusOK, "POST", "/v1/tenants/"+aid+"/keys:rotate", nil); got["version"] != 2.0 {
		t.Fatalf("rotate: %v", got)
	}
	if _, dk2 := notes.post("/v1/apps/notes/tenants/"+aid+"/data-keys", nil); dk2["key_version"] != 2.0 {
		t.Fatalf("new data key after rotation: %v", dk2)
	}
	if code, _ := unwrap(notes, aid, dk["wrapped"]); code != 200 {
		t.Fatalf("a data key of the retired version: %d", code)
	}

	// the tenant brings its own key: every version is sealed under it
	transit := newFakeTransit(t)
	byok := map[string]any{"provider": "transit", "config": map[string]any{"addr": transit.srv.URL, "token": "tenant-token",
		"key": "acme-key"}}
	if code, out := alice.do("PUT", "/v1/tenants/"+aid+"/keys/provider", map[string]any{"provider": "transit",
		"config": map[string]any{"addr": transit.srv.URL, "token": "wrong", "key": "acme-key"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("a key that does not work was accepted: %d %v", code, out)
	}
	if code, _ := alice.do("PUT", "/v1/tenants/"+aid+"/keys/provider", map[string]any{"provider": "awskms",
		"config": map[string]any{"key_id": "arn:aws:kms:x"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("a provider the installation did not enable: %d", code)
	}
	info = alice.must(http.StatusOK, "PUT", "/v1/tenants/"+aid+"/keys/provider", byok)
	if p := info["provider"].(map[string]any); p["provider"] != "transit" || !strings.HasSuffix(p["key_ref"].(string), "/transit/acme-key") ||
		strings.Contains(strings.ToLower(jsonString(info)), "tenant-token") {
		t.Fatalf("provider: %v", info)
	}
	for _, v := range info["versions"].([]any) {
		if v.(map[string]any)["sealed_by"] != "customer" {
			t.Fatalf("a version is not sealed by the tenant's key: %v", info)
		}
	}
	time.Sleep(200 * time.Millisecond) // past the cache
	if code, _ := unwrap(notes, aid, dk["wrapped"]); code != 200 {
		t.Fatalf("unwrap through the tenant's key: %d", code)
	}

	// the tenant revokes its key: its data stops opening (after the cache), and works again when restored
	transit.revoked.Store(true)
	time.Sleep(200 * time.Millisecond)
	if code, out := unwrap(notes, aid, dk["wrapped"]); code != http.StatusServiceUnavailable || out["type"] != "https://matura.dev/problems/tenant-key-unavailable" {
		t.Fatalf("after revoking the tenant's key: %d %v", code, out)
	}
	if _, err := ring.Open(sinkSecret, "audit_sink:"+sinkID); err == nil {
		t.Fatal("a tenant secret opened with the tenant's key revoked")
	}
	if code, _ := unwrap(notes, bid, mustDataKey(t, notes, bid)); code != 200 {
		t.Fatalf("another tenant was affected: %d", code)
	}
	transit.revoked.Store(false)
	if code, _ := unwrap(notes, aid, dk["wrapped"]); code != 200 {
		t.Fatalf("after restoring the tenant's key: %d", code)
	}
	alice.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+aid+"/keys/provider", nil)
	transit.revoked.Store(true) // no longer needed
	time.Sleep(200 * time.Millisecond)
	if code, _ := unwrap(notes, aid, dk["wrapped"]); code != 200 {
		t.Fatalf("back on the installation's key: %d", code)
	}

	// deleting the tenant destroys its keys: crypto-shredding
	op.must(http.StatusAccepted, "DELETE", "/v1/tenants/"+aid+"?grace_days=0", nil)
	purger := &lifecycle.Purger{Store: st}
	if _, _, err := purger.Round(ctx); err != nil {
		t.Fatal(err)
	}
	notes.post("/v1/apps/notes/placements/"+aid+":deleted", nil)
	if _, _, err := purger.Round(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	asOperator(t, pool, `SELECT status FROM tenant WHERE id = $1`, []any{aid}, &status)
	if status != "deleted" {
		t.Fatalf("tenant not deleted: %s", status)
	}
	if code, out := unwrap(notes, aid, dk["wrapped"]); code != http.StatusNotFound && code != http.StatusGone {
		t.Fatalf("a data key of a deleted tenant: %d %v", code, out)
	}
	if _, err := ring.Open(sinkSecret, "audit_sink:"+sinkID); !errors.Is(err, store.ErrTenantKeyDestroyed) {
		t.Fatalf("a deleted tenant's secret: %v", err)
	}
	var live int
	asOperator(t, pool, `SELECT count(*) FROM tenant_key WHERE tenant_id = $1 AND wrapped IS NOT NULL`, []any{aid}, &live)
	if live != 0 {
		t.Fatalf("key material left after deletion: %d", live)
	}
	if code, _ := unwrap(notes, bid, mustDataKey(t, notes, bid)); code != 200 {
		t.Fatalf("another tenant after the deletion: %d", code)
	}
}

func mustDataKey(t *testing.T, a appClient, tid string) any {
	t.Helper()
	code, dk := a.post("/v1/apps/"+a.clientID+"/tenants/"+tid+"/data-keys", nil)
	if code != http.StatusCreated {
		t.Fatalf("data key for %s: %d %v", tid, code, dk)
	}
	return dk["wrapped"]
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestRewrapSecrets: after a key-encryption key rotation every stored secret is sealed under the new key, so the old
// one can be dropped.
func TestRewrapSecrets(t *testing.T) {
	srv, st, ring, pool := setupKeys(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/webhooks", map[string]any{"url": "https://notes.example.test/hook"})
	alice := client{t: t, srv: srv, user: ids.New()}
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+aid+"/audit/sinks", map[string]any{"url": "https://siem.example.test/hook"})

	newKEK, _ := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	rotated := secrets.NewRing(newKEK, ring.Primary())
	st.EnableTenantKeys(rotated, nil, time.Millisecond) // the server's view after a restart with the new key first
	res, err := st.RewrapSecrets(ctx, rotated)
	if err != nil || res.Rewrapped < 2 || len(res.Failed) != 0 {
		t.Fatalf("rewrap: %+v %v", res, err)
	}
	if again, _ := st.RewrapSecrets(ctx, rotated); again.Rewrapped != 0 {
		t.Fatalf("second rewrap changed %d", again.Rewrapped)
	}
	// only the new KEK now: the webhook secret and the tenant's key still open
	only := secrets.NewRing(newKEK)
	st.EnableTenantKeys(only, nil, time.Millisecond)
	var id string
	var whSecret []byte
	asOperator(t, pool, `SELECT id::text, secret FROM webhook_endpoint`, nil, &id, &whSecret)
	if _, err := only.Open(whSecret, "webhook:"+id); err != nil {
		t.Fatalf("webhook secret after rewrap: %v", err)
	}
	var sinkID string
	var sinkSecret []byte
	asOperator(t, pool, `SELECT id::text, secret FROM audit_sink`, nil, &sinkID, &sinkSecret)
	if _, err := only.Open(sinkSecret, "audit_sink:"+sinkID); err != nil {
		t.Fatalf("tenant secret after rewrap: %v", err)
	}
	if code, _ := alice.do("POST", "/admin/v1/keys:rewrap", nil); code != http.StatusForbidden {
		t.Fatalf("a tenant owner rewraps: %d", code)
	}
}
