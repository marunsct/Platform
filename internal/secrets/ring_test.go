package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localKEK(t *testing.T, b byte) *Local {
	t.Helper()
	l, err := NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestRingSealsOpensAndRotates(t *testing.T) {
	oldKEK, newKEK := localKEK(t, 1), localKEK(t, 2)
	legacy, err := oldKEK.Seal([]byte("v1 secret"), "row:1")
	if err != nil {
		t.Fatal(err)
	}
	ring := NewRing(oldKEK)
	if got, err := ring.Open(legacy, "row:1"); err != nil || string(got) != "v1 secret" {
		t.Fatalf("version 1 through the ring: %q %v", got, err)
	}
	ct, err := ring.Seal([]byte("hello"), "row:2")
	if err != nil || ct[0] != ringVersion || KeyID(ct) != oldKEK.ID() {
		t.Fatalf("seal: %v %v", ct, err)
	}
	if _, err := ring.Open(ct, "row:3"); err == nil {
		t.Fatal("opened under another row's associated data")
	}
	if ring.Fingerprint([]byte("pw")) != oldKEK.Fingerprint([]byte("pw")) {
		t.Fatal("fingerprints changed with the ring")
	}

	// rotation: the new KEK is primary, the old one still opens
	rotated := NewRing(newKEK, oldKEK)
	if got, err := rotated.Open(ct, "row:2"); err != nil || string(got) != "hello" {
		t.Fatalf("old secret after rotation: %q %v", got, err)
	}
	re, changed, err := rotated.Rewrap(legacy, "row:1")
	if err != nil || !changed || KeyID(re) != newKEK.ID() {
		t.Fatalf("rewrap: %v %v %s", changed, err, KeyID(re))
	}
	if _, changed, _ := rotated.Rewrap(re, "row:1"); changed {
		t.Fatal("rewrapping a current secret changed it")
	}
	if got, err := NewRing(newKEK).Open(re, "row:1"); err != nil || string(got) != "v1 secret" {
		t.Fatalf("rewrapped without the old KEK: %q %v", got, err)
	}
	if _, err := NewRing(newKEK).Open(ct, "row:2"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown KEK: %v", err)
	}
	if _, err := ring.Open([]byte{2, 3, 'a'}, "x"); err == nil {
		t.Fatal("garbage opened")
	}
}

// fakeKMS answers like a key service: it encrypts with a local key, checks associated data, and refuses with 403
// once revoked.
type fakeKMS struct {
	t       *testing.T
	key     *Local
	revoked atomic.Bool
	calls   atomic.Int32
	check   func(r *http.Request, body []byte)
}

func (f *fakeKMS) seal(plain, aad []byte) []byte {
	ct, _ := f.key.Wrap(context.Background(), plain, aad)
	return ct
}

func (f *fakeKMS) open(ct, aad []byte) ([]byte, bool) {
	p, err := f.key.Unwrap(context.Background(), ct, aad)
	return p, err == nil
}

func (f *fakeKMS) deny(w http.ResponseWriter) bool {
	f.calls.Add(1)
	if f.revoked.Load() {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return true
	}
	return false
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func (f *fakeKMS) server(handle func(w http.ResponseWriter, r *http.Request, body map[string]any)) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		if f.check != nil {
			f.check(r, raw.Bytes())
		}
		if f.deny(w) {
			return
		}
		var body map[string]any
		_ = json.Unmarshal(raw.Bytes(), &body)
		w.Header().Set("Content-Type", "application/json")
		handle(w, r, body)
	}))
	f.t.Cleanup(srv.Close)
	return srv
}

func roundTrip(t *testing.T, w Wrapper) {
	t.Helper()
	ring := NewRing(w)
	ct, err := ring.Seal([]byte("secret value"), "tenant_sso:1")
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(ct) != w.ID() {
		t.Fatalf("key id %s", KeyID(ct))
	}
	if got, err := ring.Open(ct, "tenant_sso:1"); err != nil || string(got) != "secret value" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := ring.Open(ct, "tenant_sso:2"); err == nil {
		t.Fatal("opened with another row's associated data")
	}
}

func TestTransit(t *testing.T) {
	f := &fakeKMS{t: t, key: localKEK(t, 9)}
	srv := f.server(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if r.Header.Get("X-Vault-Token") != "s.token" || r.Header.Get("X-Vault-Namespace") != "acme" {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		aad := unb64(body["associated_data"].(string))
		switch r.URL.Path {
		case "/v1/transit/encrypt/matura":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"ciphertext": "vault:v1:" + b64(f.seal(unb64(body["plaintext"].(string)), aad))}})
		case "/v1/transit/decrypt/matura":
			p, ok := f.open(unb64(strings.TrimPrefix(body["ciphertext"].(string), "vault:v1:")), aad)
			if !ok {
				http.Error(w, `{"errors":["cipher: message authentication failed"]}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": b64(p)}})
		default:
			http.NotFound(w, r)
		}
	})
	tr := &Transit{Addr: srv.URL, Token: "s.token", Namespace: "acme"}
	if tr.ID() != "transit:transit/matura" {
		t.Fatal(tr.ID())
	}
	roundTrip(t, tr)
	ct, _ := NewRing(tr).Seal([]byte("x"), "a")
	f.revoked.Store(true)
	_, err := NewRing(tr).Open(ct, "a")
	var pe *ProviderError
	if !errors.As(err, &pe) || !pe.Denied() {
		t.Fatalf("revoked transit key: %v", err)
	}
}

func TestAWSKMS(t *testing.T) {
	f := &fakeKMS{t: t, key: localKEK(t, 8)}
	f.check = func(r *http.Request, _ []byte) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(auth, "/eu-west-1/kms/aws4_request") ||
			r.Header.Get("X-Amz-Security-Token") != "session" || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
			t.Errorf("request not signed for KMS: %s", auth)
		}
	}
	srv := f.server(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if body["KeyId"] != "arn:aws:kms:eu-west-1:1:key/k" {
			http.Error(w, "wrong key", http.StatusBadRequest)
			return
		}
		aad := []byte(body["EncryptionContext"].(map[string]any)["matura"].(string))
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			_ = json.NewEncoder(w).Encode(map[string]any{"CiphertextBlob": b64(f.seal(unb64(body["Plaintext"].(string)), aad))})
		case "TrentService.Decrypt":
			p, ok := f.open(unb64(body["CiphertextBlob"].(string)), aad)
			if !ok {
				http.Error(w, `{"__type":"InvalidCiphertextException"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Plaintext": b64(p)})
		}
	})
	roundTrip(t, &AWSKMS{KeyID: "arn:aws:kms:eu-west-1:1:key/k", Region: "eu-west-1", Endpoint: srv.URL,
		Creds: func() (AWSCredentials, error) { return AWSCredentials{"AKID", "secret", "session"}, nil }})
}

// TestSigV4 checks the signer against AWS's documented example (IAM ListUsers, 2015-08-30).
func TestSigV4(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signV4(req, nil, AWSCredentials{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", ""}, "us-east-1", "iam",
		time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("signature:\n got %s\nwant %s", got, want)
	}
}

func TestGCPKMS(t *testing.T) {
	f := &fakeKMS{t: t, key: localKEK(t, 7)}
	key := "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	srv := f.server(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if r.Header.Get("Authorization") != "Bearer ya29.token" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		aad := unb64(body["additionalAuthenticatedData"].(string))
		switch r.URL.Path {
		case "/v1/" + key + ":encrypt":
			_ = json.NewEncoder(w).Encode(map[string]any{"ciphertext": b64(f.seal(unb64(body["plaintext"].(string)), aad))})
		case "/v1/" + key + ":decrypt":
			p, ok := f.open(unb64(body["ciphertext"].(string)), aad)
			if !ok {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": b64(p)})
		default:
			http.NotFound(w, r)
		}
	})
	roundTrip(t, &GCPKMS{Key: key, Endpoint: srv.URL, Tokens: StaticToken("ya29.token")})
}

func TestAzureKeyVault(t *testing.T) {
	f := &fakeKMS{t: t, key: localKEK(t, 6)}
	srv := f.server(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if r.Header.Get("Authorization") != "Bearer az" || r.URL.Query().Get("api-version") != "7.4" || body["alg"] != "RSA-OAEP-256" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		v, _ := base64.RawURLEncoding.DecodeString(body["value"].(string))
		var out []byte
		switch {
		case strings.HasSuffix(r.URL.Path, "/wrapkey"):
			out = f.seal(v, nil)
		case strings.HasSuffix(r.URL.Path, "/unwrapkey"):
			p, ok := f.open(v, nil)
			if !ok {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			out = p
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kid": "k", "value": base64.RawURLEncoding.EncodeToString(out)})
	})
	roundTrip(t, &AzureKeyVault{KeyURL: srv.URL + "/keys/matura/1", Tokens: StaticToken("az")})
}

func TestMetadataTokenCaches(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		n.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	}))
	defer srv.Close()
	m := GoogleMetadataToken()
	m.URL = srv.URL
	for range 3 {
		if tok, err := m.Token(context.Background()); err != nil || tok != "tok" {
			t.Fatalf("%q %v", tok, err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("fetched %d times", n.Load())
	}
}
