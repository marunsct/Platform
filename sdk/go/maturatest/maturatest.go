// Package maturatest is a fake Matura issuer for tests: mint tokens for any tenant, roles and permissions without
// Keycloak, and sign events as Matura's webhooks do.
package maturatest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	matura "github.com/marunsct/Platform/sdk/go"
)

// Issuer signs tokens shaped like Matura's (contract §2) with an RS256 key of its own.
type Issuer struct {
	Issuer   string
	Audience string
	Kid      string
	key      *rsa.PrivateKey
}

// NewIssuer returns an issuer; empty values default to https://matura.test/realms/matura and "app".
func NewIssuer(issuer, audience string) (*Issuer, error) {
	if issuer == "" {
		issuer = "https://matura.test/realms/matura"
	}
	if audience == "" {
		audience = "app"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := make([]byte, 8)
	_, _ = rand.Read(kid)
	return &Issuer{Issuer: issuer, Audience: audience, Kid: hex.EncodeToString(kid), key: key}, nil
}

// JWKS is the issuer's public key set.
func (i *Issuer) JWKS() *matura.JWKS {
	pub := i.key.PublicKey
	return &matura.JWKS{Keys: []matura.JWK{{
		Kty: "RSA", Kid: i.Kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// Verifier returns a verifier that trusts this issuer (no network).
func (i *Issuer) Verifier() *matura.Verifier {
	v, _ := matura.NewVerifier(matura.VerifierOptions{Issuer: i.Issuer, Audience: i.Audience, JWKS: i.JWKS()})
	return v
}

// Sign signs arbitrary claims with the issuer's key (RS256).
func (i *Issuer) Sign(claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": i.Kid})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// TokenOptions shape a token; zero values get the same defaults as the Python and TypeScript fake issuers.
type TokenOptions struct {
	UserID      string // default: a random UUID
	TenantID    string
	Tenant      string // tenant slug (default: the first 8 characters of TenantID)
	WorkspaceID string
	TenantRoles []string // default member
	Roles       []string
	Perms       []string
	Email       string
	Name        string
	TTL         time.Duration // default 5 minutes; negative for an expired token
	Audience    string
	Now         time.Time
	Extra       map[string]any // extra or overriding claims
}

// Token returns a Matura-shaped access token.
func (i *Issuer) Token(o TokenOptions) (string, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	sub := o.UserID
	if sub == "" {
		sub = uuid()
	}
	aud := o.Audience
	if aud == "" {
		aud = i.Audience
	}
	email := o.Email
	if email == "" {
		email = sub[:min(8, len(sub))] + "@example.test"
	}
	name := o.Name
	if name == "" {
		name = "Test User"
	}
	troles := o.TenantRoles
	if len(troles) == 0 {
		troles = []string{"member"}
	}
	claims := map[string]any{
		"iss": i.Issuer, "aud": aud, "sub": sub, "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "email": email,
		"email_verified": true, "name": name, "troles": troles, "roles": nonNil(o.Roles), "perms": nonNil(o.Perms),
		"ver": map[string]int{"u": 1, "m": 1, "t": 1}, "azp": aud,
	}
	if o.TenantID != "" {
		slug := o.Tenant
		if slug == "" {
			slug = o.TenantID[:min(8, len(o.TenantID))]
		}
		claims["tid"], claims["tenant"], claims["pmode"] = o.TenantID, slug, "shared"
	}
	if o.WorkspaceID != "" {
		claims["wid"] = o.WorkspaceID
	}
	for k, v := range o.Extra {
		claims[k] = v
	}
	return i.Sign(claims)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// SignedEvent returns the body and headers of a webhook as Matura sends it, signed at the given time (zero: now).
func SignedEvent(secret []byte, event any, at time.Time) ([]byte, http.Header, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return nil, nil, err
	}
	if at.IsZero() {
		at = time.Now()
	}
	var id struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &id)
	h := http.Header{}
	h.Set("Matura-Signature", matura.Sign(secret, at, body))
	h.Set("Matura-Event-Id", id.ID)
	h.Set("Content-Type", "application/cloudevents+json")
	return body, h, nil
}
