package matura_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	matura "github.com/marunsct/Platform/sdk/go"
	"github.com/marunsct/Platform/sdk/go/maturatest"
)

func newIssuer(t *testing.T) *maturatest.Issuer {
	t.Helper()
	iss, err := maturatest.NewIssuer("", "notes")
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func mustToken(t *testing.T, iss *maturatest.Issuer, o maturatest.TokenOptions) string {
	t.Helper()
	tok, err := iss.Token(o)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestVerifyChecksClaims(t *testing.T) {
	iss := newIssuer(t)
	v := iss.Verifier()
	ctx := context.Background()
	tid := "0192b7a4-6000-7000-8000-000000000001"
	p, err := v.Verify(ctx, mustToken(t, iss, maturatest.TokenOptions{TenantID: tid, Perms: []string{"note.read"},
		Roles: []string{"reader"}, Extra: map[string]any{"amr": []string{"pwd", "otp"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if p.TenantID != tid || p.TenantSlug != tid[:8] || !p.Has("note.read") || p.Has("note.write") || !p.MFA ||
		p.PlacementMode != "shared" || p.ClientID != "notes" || p.IsService || p.Claims.Versions["m"] != 1 {
		t.Fatalf("principal = %+v", p)
	}

	bad := map[string]string{
		"expired":        mustToken(t, iss, maturatest.TokenOptions{TTL: -time.Minute}),
		"other audience": mustToken(t, iss, maturatest.TokenOptions{Audience: "billing"}),
		"not yet valid":  mustToken(t, iss, maturatest.TokenOptions{Extra: map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}}),
		"exp a string":   mustToken(t, iss, maturatest.TokenOptions{Extra: map[string]any{"exp": "soon"}}),
		"no sub":         mustToken(t, iss, maturatest.TokenOptions{Extra: map[string]any{"sub": nil}}),
		"other issuer":   mustToken(t, iss, maturatest.TokenOptions{Extra: map[string]any{"iss": "https://evil.test"}}),
		"garbage":        "a.b.c",
		"two parts":      "a.b",
	}
	for name, tok := range bad {
		if _, err := v.Verify(ctx, tok); !errors.Is(err, matura.ErrInvalidToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// within the 30 s leeway
	if _, err := v.Verify(ctx, mustToken(t, iss, maturatest.TokenOptions{TTL: -10 * time.Second})); err != nil {
		t.Errorf("leeway: %v", err)
	}
	// an audience list that names the app
	if _, err := v.Verify(ctx, mustToken(t, iss, maturatest.TokenOptions{Extra: map[string]any{"aud": []string{"x", "notes"}}})); err != nil {
		t.Errorf("audience list: %v", err)
	}
}

func TestVerifyRefusesHMACAndNone(t *testing.T) {
	iss := newIssuer(t)
	v := iss.Verifier()
	claims := b64(map[string]any{"iss": iss.Issuer, "aud": "notes", "sub": "u", "exp": time.Now().Add(time.Minute).Unix()})
	// HS256 signed with the RSA modulus as the secret: the classic key-confusion attack
	h := b64(map[string]any{"alg": "HS256", "kid": iss.Kid})
	m := hmac.New(sha256.New, []byte(iss.JWKS().Keys[0].N))
	m.Write([]byte(h + "." + claims))
	for _, tok := range []string{
		h + "." + claims + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)),
		b64(map[string]any{"alg": "none"}) + "." + claims + ".",
	} {
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, matura.ErrInvalidToken) {
			t.Errorf("err = %v", err)
		}
	}
}

func sign(t *testing.T, alg string, key crypto.Signer, kid string, claims map[string]any) string {
	t.Helper()
	input := b64(map[string]any{"alg": alg, "kid": kid}) + "." + b64(claims)
	h := crypto.SHA256
	if alg == "ES384" {
		h = crypto.SHA384
	}
	d := h.New()
	d.Write([]byte(input))
	sum := d.Sum(nil)
	var sig []byte
	var err error
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		r, s, e := ecdsa.Sign(rand.Reader, k, sum)
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
		err = e
	case *rsa.PrivateKey:
		sig, err = rsa.SignPSS(rand.Reader, k, h, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func ecJWK(k *ecdsa.PrivateKey, kid, crv string) matura.JWK {
	size := (k.Curve.Params().BitSize + 7) / 8
	x, y := make([]byte, size), make([]byte, size)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return matura.JWK{Kty: "EC", Kid: kid, Crv: crv, X: base64.RawURLEncoding.EncodeToString(x),
		Y: base64.RawURLEncoding.EncodeToString(y)}
}

func TestVerifyECAndPSS(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := &matura.JWKS{Keys: []matura.JWK{ecJWK(ec256, "e1", "P-256"), ecJWK(ec384, "e2", "P-384"), {Kty: "RSA",
		Kid: "r1", N: base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()), E: "AQAB"}}}
	v, err := matura.NewVerifier(matura.VerifierOptions{Issuer: "https://i.test/", Audience: "a", JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "https://i.test", "aud": "a", "sub": "u", "exp": time.Now().Add(time.Minute).Unix()}
	for _, tok := range []string{
		sign(t, "ES256", ec256, "e1", claims), sign(t, "ES384", ec384, "e2", claims), sign(t, "PS256", rsaKey, "r1", claims),
	} {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Errorf("verify: %v", err)
		}
	}
	// a P-256 signature under the P-384 key's kid
	if _, err := v.Verify(context.Background(), sign(t, "ES256", ec256, "e2", claims)); err == nil {
		t.Error("wrong curve accepted")
	}
}

func TestJWKSFetchCacheAndRotation(t *testing.T) {
	first, second := newIssuer(t), newIssuer(t)
	second.Issuer = first.Issuer
	var mu sync.Mutex
	keys := first.JWKS()
	var fetches atomic.Int32
	fail := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(keys)
	}))
	defer srv.Close()
	now := time.Now()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	v, err := matura.NewVerifier(matura.VerifierOptions{Issuer: first.Issuer, Audience: "notes", JWKSURL: srv.URL,
		Now: func() time.Time { return time.Unix(0, clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok1 := mustToken(t, first, maturatest.TokenOptions{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(ctx, tok1); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (cached)", n)
	}

	// the realm rotates its key: an unknown kid refetches, but not more than every 10 s
	mu.Lock()
	keys = second.JWKS()
	mu.Unlock()
	tok2 := mustToken(t, second, maturatest.TokenOptions{TTL: time.Hour})
	if _, err := v.Verify(ctx, tok2); !errors.Is(err, matura.ErrInvalidToken) {
		t.Fatalf("too soon after the last fetch: %v", err)
	}
	clock.Add(int64(11 * time.Second))
	if _, err := v.Verify(ctx, tok2); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}

	// the endpoint fails after the cache expired: the known keys keep working
	fail.Store(true)
	clock.Add(int64(6 * time.Minute))
	if _, err := v.Verify(ctx, tok2); err != nil {
		t.Fatalf("with the endpoint down: %v", err)
	}
	if _, err := v.Verify(ctx, tok2); err != nil {
		t.Fatal(err)
	}
	if n := fetches.Load(); n != 3 {
		t.Fatalf("fetches = %d, want 3 (one failed attempt, then a pause)", n)
	}
}

func TestBearer(t *testing.T) {
	for in, want := range map[string]string{"Bearer abc": "abc", "bearer  abc ": "abc"} {
		if got, err := matura.Bearer(in); err != nil || got != want {
			t.Errorf("Bearer(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Basic abc", "Bearer", "Bearer  "} {
		if _, err := matura.Bearer(in); !errors.Is(err, matura.ErrInvalidToken) {
			t.Errorf("Bearer(%q): %v", in, err)
		}
	}
}

func TestPrincipalExpandAndService(t *testing.T) {
	c := &matura.Claims{Subject: "svc", Roles: []string{"reader", "writer"}, PermsRef: "r1",
		Raw: map[string]any{"client_id": "worker"}, ClientID: "worker"}
	p := matura.PrincipalFromClaims(c)
	if !p.IsService || p.ClientID != "worker" || p.Has("note.read") {
		t.Fatalf("principal = %+v", p)
	}
	e := p.Expand(map[string][]string{"reader": {"note.read"}, "writer": {"note.write", "note.read"}})
	if e.PermsRef != "" || len(e.Permissions) != 2 || e.Permissions[0] != "note.read" || !e.Has("note.write") {
		t.Fatalf("expanded = %v", e.Permissions)
	}
	if all := p.Expand(map[string][]string{"reader": {"*"}}); !all.Has("anything") {
		t.Fatal("* not expanded")
	}
	if err := p.RequirePermission("note.read"); !errors.Is(err, matura.ErrForbidden) {
		t.Fatalf("RequirePermission: %v", err)
	}
	if err := p.RequireRole("writer"); err != nil {
		t.Fatal(err)
	}
	if err := p.RequireTenant(); !errors.Is(err, matura.ErrForbidden) {
		t.Fatal("no tenant accepted")
	}
}
