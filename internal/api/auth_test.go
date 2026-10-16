package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestJWTAuthenticator(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := JWTAuthenticator{
		Keyfunc:      func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		Issuer:       "https://id.example.test/realms/matura",
		Audience:     "matura-api",
		OperatorRole: "matura-operator",
	}
	sub := uuid.New()
	sign := func(k *ecdsa.PrivateKey, mod func(jwt.MapClaims)) string {
		c := jwt.MapClaims{
			"iss": a.Issuer, "aud": "matura-api", "sub": sub.String(), "exp": time.Now().Add(time.Minute).Unix(),
			"email": "ana@acme.test", "email_verified": true, "name": "Ana",
			"realm_access": map[string]any{"roles": []string{"matura-operator"}},
		}
		if mod != nil {
			mod(c)
		}
		s, err := jwt.NewWithClaims(jwt.SigningMethodES256, c).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	check := func(token string) (Principal, error) {
		r := httptest.NewRequest("GET", "/v1/me", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return a.Authenticate(r)
	}

	p, err := check(sign(key, nil))
	if err != nil || p.UserID != sub || !p.Operator || p.Email != "ana@acme.test" || !p.EmailVerified {
		t.Fatalf("valid token: %+v %v", p, err)
	}
	for name, token := range map[string]string{
		"missing":        "",
		"wrong key":      sign(other, nil),
		"expired":        sign(key, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no expiry":      sign(key, func(c jwt.MapClaims) { delete(c, "exp") }),
		"wrong issuer":   sign(key, func(c jwt.MapClaims) { c["iss"] = "https://evil.test" }),
		"wrong audience": sign(key, func(c jwt.MapClaims) { c["aud"] = "devflow" }),
		"bad subject":    sign(key, func(c jwt.MapClaims) { c["sub"] = "service-account-x" }),
	} {
		if _, err := check(token); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p, _ = check(sign(key, func(c jwt.MapClaims) { delete(c, "realm_access") }))
	if p.Operator {
		t.Error("operator without the realm role")
	}
}
