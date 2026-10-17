package events

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

func TestSignVerify(t *testing.T) {
	key := []byte("whsec_test")
	body := []byte(`{"id":"evt_1"}`)
	now := time.Unix(1792140300, 0)
	h := Sign(key, now, body)
	if err := Verify(key, h, body, now.Add(time.Minute)); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	cases := map[string]func() error{
		"other body":   func() error { return Verify(key, h, []byte(`{"id":"evt_2"}`), now) },
		"other key":    func() error { return Verify([]byte("x"), h, body, now) },
		"too old":      func() error { return Verify(key, h, body, now.Add(6*time.Minute)) },
		"future":       func() error { return Verify(key, h, body, now.Add(-6*time.Minute)) },
		"no signature": func() error { return Verify(key, "t=1792140300", body, now) },
		"garbage":      func() error { return Verify(key, "nonsense", body, now) },
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a rotated secret: either v1 may match
	rotated := h + ",v1=" + strings.Repeat("0", 64)
	if err := Verify(key, rotated, body, now); err != nil {
		t.Fatalf("two signatures: %v", err)
	}
}

func TestEnvelope(t *testing.T) {
	tid := uuid.MustParse("0192b7a4-6000-7000-8000-000000000001")
	c := store.Change{Seq: 9, ID: 42, Type: "matura.membership.added", Subject: "tenants/x/members/y", TenantID: &tid,
		Version: 40, Time: time.Unix(0, 0), Payload: json.RawMessage(`{"tenant_role":"admin"}`)}
	b, err := json.Marshal(FromChange("matura://installation/test", c))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("not JSON: %s", b)
	}
	data := got["data"].(map[string]any)
	if got["id"] != "evt_42" || got["sequence"] != "9" || got["tenantid"] != tid.String() || data["object"] != "membership" ||
		data["version"].(float64) != 40 || data["membership"].(map[string]any)["tenant_role"] != "admin" {
		t.Fatalf("envelope: %s", b)
	}
	for typ, want := range map[string]string{"matura.app.role.updated": "app_role", "matura.tenant_app.enabled": "tenant_app",
		"matura.user.deleted": "user", "matura.app.manifest.updated": "app_manifest"} {
		if got := ObjectOf(typ); got != want {
			t.Errorf("ObjectOf(%s) = %s, want %s", typ, got, want)
		}
	}
}

// TestSharedVectors: the Go verifier agrees with docs/contract/test-vectors.json, which every SDK also checks.
func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../docs/contract/test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Secret     string `json:"secret"`
		Signatures []struct {
			Name, Body, Header string
			Now                int64
			Valid              bool
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, s := range v.Signatures {
		err := Verify([]byte(v.Secret), s.Header, []byte(s.Body), time.Unix(s.Now, 0))
		if (err == nil) != s.Valid {
			t.Errorf("%s: err=%v, want valid=%v", s.Name, err, s.Valid)
		}
	}
}
