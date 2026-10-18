package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func key(t *testing.T) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestSealOpen(t *testing.T) {
	km, err := NewLocal(key(t))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := km.Seal([]byte("s3cret"), "db_server:1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("s3cret")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := km.Open(ct, "db_server:1")
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := km.Open(ct, "db_server:2"); err == nil {
		t.Fatal("opened under another row's associated data")
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 1
	if _, err := km.Open(tampered, "db_server:1"); err == nil {
		t.Fatal("opened a tampered secret")
	}
	other, _ := NewLocal(key(t))
	if _, err := other.Open(ct, "db_server:1"); err == nil {
		t.Fatal("opened with another key-encryption key")
	}
	ct2, _ := km.Seal([]byte("s3cret"), "db_server:1")
	if bytes.Equal(ct, ct2) {
		t.Fatal("sealing is deterministic")
	}
	if km.Fingerprint([]byte("a")) == km.Fingerprint([]byte("b")) {
		t.Fatal("fingerprints collide")
	}
}

func TestBadKEK(t *testing.T) {
	for _, k := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := NewLocal(k); err == nil {
			t.Errorf("accepted KEK %q", k)
		}
	}
}
