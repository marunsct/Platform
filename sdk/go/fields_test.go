package matura_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	matura "github.com/marunsct/Platform/sdk/go"
)

func TestFieldCipher(t *testing.T) {
	keys := map[string][]byte{} // wrapped -> plain, as maturad keeps them sealed
	var destroyed atomic.Bool
	var issued, unwrapped atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case destroyed.Load():
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"detail":"destroyed"}`))
		case r.URL.Path == "/v1/apps/notes/tenants/t1/data-keys":
			issued.Add(1)
			plain, wrapped := make([]byte, 32), make([]byte, 48)
			_, _ = rand.Read(plain)
			_, _ = rand.Read(wrapped)
			keys[string(wrapped)] = plain
			_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": plain, "wrapped": wrapped, "key_version": 1})
		case r.URL.Path == "/v1/apps/notes/tenants/t1/data-keys:unwrap":
			unwrapped.Add(1)
			var in struct{ Wrapped []byte }
			_ = json.NewDecoder(r.Body).Decode(&in)
			_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": keys[string(in.Wrapped)]})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	f := &matura.FieldCipher{Client: matura.NewClient(srv.URL, "notes", "s"), App: "notes"}
	a, err := f.Encrypt(ctx, "t1", []byte("ana@acme.com"), []byte("users.email:1"))
	if err != nil || !strings.HasPrefix(a, "mfe1:") || strings.Contains(a, "ana@") {
		t.Fatalf("encrypt: %q %v", a, err)
	}
	b, _ := f.Encrypt(ctx, "t1", []byte("bo@acme.com"), []byte("users.email:2"))
	if issued.Load() != 1 {
		t.Fatalf("a data key per value: %d", issued.Load())
	}
	if got, err := f.Decrypt(ctx, "t1", a, []byte("users.email:1")); err != nil || string(got) != "ana@acme.com" {
		t.Fatalf("decrypt: %q %v", got, err)
	}
	if _, err := f.Decrypt(ctx, "t1", b, []byte("users.email:1")); err == nil {
		t.Fatal("decrypted with another row's aad")
	}
	if _, err := f.Decrypt(ctx, "t2", a, []byte("users.email:1")); err == nil {
		t.Fatal("decrypted as another tenant")
	}
	// a fresh process unwraps through maturad
	g := &matura.FieldCipher{Client: matura.NewClient(srv.URL, "notes", "s"), App: "notes"}
	if got, err := g.Decrypt(ctx, "t1", a, []byte("users.email:1")); err != nil || string(got) != "ana@acme.com" || unwrapped.Load() != 1 {
		t.Fatalf("decrypt elsewhere: %q %v (%d unwraps)", got, err, unwrapped.Load())
	}
	// after the tenant is deleted: gone
	destroyed.Store(true)
	h := &matura.FieldCipher{Client: matura.NewClient(srv.URL, "notes", "s"), App: "notes"}
	if _, err := h.Decrypt(ctx, "t1", a, []byte("users.email:1")); !errors.Is(err, matura.ErrTenantKeyDestroyed) {
		t.Fatalf("after deletion: %v", err)
	}
	if _, err := h.Decrypt(ctx, "t1", "plain text", nil); err == nil {
		t.Fatal("decrypted a plain value")
	}
}
