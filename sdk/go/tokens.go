package matura

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrInvalidToken: the token is missing, malformed, expired, for another audience or signed by an unknown key
// (answer 401). Errors from Verify wrap it.
var ErrInvalidToken = errors.New("invalid token")

// ErrForbidden: the caller lacks a permission, role or tenant (answer 403).
var ErrForbidden = errors.New("forbidden")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, a...))
}

// Algorithms Matura tokens may use. "none" and HMAC (HS*) are always refused.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384"}

var algHash = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512, "PS256": crypto.SHA256,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384,
}

// VerifierOptions configure a Verifier. Issuer and Audience are required.
type VerifierOptions struct {
	Issuer   string // https://<matura-host>/realms/matura; a trailing slash is ignored
	Audience string // the app's client id
	JWKSURL  string // default Issuer + "/protocol/openid-connect/certs"
	// JWKS is a static key set (no network), for tests with maturatest.FakeIssuer or pinned keys.
	JWKS       *JWKS
	Leeway     time.Duration // clock skew allowed on exp and nbf (default 30s)
	CacheTTL   time.Duration // how long fetched keys are reused (default 5m)
	RefetchMin time.Duration // minimum time between refetches caused by an unknown kid (default 10s)
	Now        func() time.Time
	HTTPClient *http.Client // default: a client with a 10s timeout
	// Revocations, when set, are checked after the signature and claims: a revoked token fails like an invalid one.
	Revocations *Revocations
}

// Verifier verifies Matura access tokens: signature (JWKS, cached), issuer, audience (the app's client id), expiry.
//
// Keys come from the realm's JWKS endpoint, cached for CacheTTL; a token with an unknown kid triggers one refetch (at
// most every RefetchMin), so key rotation works without a restart. It is safe for concurrent use.
type Verifier struct {
	issuer, audience, jwksURL string
	leeway, cacheTTL, refetch time.Duration
	now                       func() time.Time
	client                    *http.Client
	static                    bool
	revocations               *Revocations

	mu        sync.Mutex // guards keys, fetchedAt and triedAt
	keys      []JWK
	fetchedAt time.Time  // last successful fetch
	triedAt   time.Time  // last attempt
	fetchMu   sync.Mutex // one fetch at a time
}

// NewVerifier returns a verifier for the issuer and audience.
func NewVerifier(o VerifierOptions) (*Verifier, error) {
	if o.Issuer == "" || o.Audience == "" {
		return nil, errors.New("matura: a verifier needs Issuer and Audience")
	}
	v := &Verifier{
		issuer: strings.TrimRight(o.Issuer, "/"), audience: o.Audience, jwksURL: o.JWKSURL,
		leeway: o.Leeway, cacheTTL: o.CacheTTL, refetch: o.RefetchMin, now: o.Now, client: o.HTTPClient,
		revocations: o.Revocations,
	}
	if v.jwksURL == "" {
		v.jwksURL = v.issuer + "/protocol/openid-connect/certs"
	}
	if v.leeway == 0 {
		v.leeway = 30 * time.Second
	}
	if v.cacheTTL == 0 {
		v.cacheTTL = 5 * time.Minute
	}
	if v.refetch == 0 {
		v.refetch = 10 * time.Second
	}
	if v.now == nil {
		v.now = time.Now
	}
	if v.client == nil {
		v.client = &http.Client{Timeout: 10 * time.Second}
	}
	if o.JWKS != nil {
		v.static, v.keys = true, slices.Clone(o.JWKS.Keys)
	}
	return v, nil
}

// Issuer is the issuer tokens must name.
func (v *Verifier) Issuer() string { return v.issuer }

// Audience is the app's client id tokens must be for.
func (v *Verifier) Audience() string { return v.audience }

func b64JSON(part string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, invalid("malformed token")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, invalid("malformed token")
	}
	return m, nil
}

// Verify checks a token and returns its principal. Errors wrap ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, token string) (*Principal, error) {
	c, err := v.VerifyClaims(ctx, token)
	if err != nil {
		return nil, err
	}
	if v.revocations != nil && v.revocations.Revoked(c) {
		return nil, invalid("token revoked")
	}
	return PrincipalFromClaims(c), nil
}

// VerifyClaims checks a token and returns its claims. Errors wrap ErrInvalidToken.
func (v *Verifier) VerifyClaims(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil, invalid("malformed token")
	}
	header, err := b64JSON(parts[0])
	if err != nil {
		return nil, err
	}
	alg, _ := header["alg"].(string)
	if !slices.Contains(Algorithms, alg) {
		return nil, invalid("the algorithm %v is not allowed", header["alg"])
	}
	kid, _ := header["kid"].(string)
	claims, err := b64JSON(parts[1])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, invalid("malformed token")
	}
	key, err := v.key(ctx, kid, alg)
	if err != nil {
		return nil, err
	}
	if !signatureOK(alg, key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, invalid("signature verification failed")
	}
	if err := v.checkClaims(claims); err != nil {
		return nil, err
	}
	return claimsFrom(claims), nil
}

func signatureOK(alg string, key crypto.PublicKey, data, sig []byte) bool {
	h := algHash[alg].New()
	h.Write(data)
	sum := h.Sum(nil)
	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(k, algHash[alg], sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(k, algHash[alg], sum, sig) == nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, sum, r, s)
	}
	return false
}

func (v *Verifier) checkClaims(c map[string]any) error {
	for _, name := range []string{"exp", "iss", "sub", "aud"} {
		if c[name] == nil {
			return invalid("the token has no %q claim", name)
		}
	}
	now := float64(v.now().UnixNano()) / 1e9
	leeway := v.leeway.Seconds()
	exp, ok := c["exp"].(float64)
	if !ok {
		return invalid("exp must be a number")
	}
	if exp <= now-leeway {
		return invalid("token expired")
	}
	if nbf, present := c["nbf"]; present {
		n, ok := nbf.(float64)
		if !ok {
			return invalid("nbf must be a number")
		}
		if n > now+leeway {
			return invalid("the token is not yet valid (nbf)")
		}
	}
	if iat, present := c["iat"]; present {
		if _, ok := iat.(float64); !ok {
			return invalid("iat must be a number")
		}
	}
	if c["iss"] != v.issuer {
		return invalid("invalid issuer")
	}
	var auds []any
	switch a := c["aud"].(type) {
	case string:
		auds = []any{a}
	case []any:
		auds = a
	}
	found := false
	for _, a := range auds {
		s, ok := a.(string)
		if !ok {
			return invalid("audience doesn't match")
		}
		found = found || s == v.audience
	}
	if !found {
		return invalid("audience doesn't match")
	}
	if sub, ok := c["sub"].(string); !ok || sub == "" {
		return invalid("sub must be a string")
	}
	return nil
}

func (v *Verifier) find(kid, alg string) *JWK {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.keys {
		k := &v.keys[i]
		if (kid == "" || k.Kid == kid) && k.fits(alg) {
			cp := *k
			return &cp
		}
	}
	return nil
}

// since is the time since t, or forever for a zero t.
func (v *Verifier) since(t *time.Time) time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	if t.IsZero() {
		return time.Duration(1<<63 - 1)
	}
	return v.now().Sub(*t)
}

func (v *Verifier) key(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	var jwk *JWK
	if v.static {
		jwk = v.find(kid, alg)
	} else {
		stale := func() bool { return v.since(&v.fetchedAt) > v.cacheTTL && v.since(&v.triedAt) >= v.refetch }
		if stale() {
			if err := v.refreshKeepingOld(ctx, stale); err != nil {
				return nil, err
			}
		}
		jwk = v.find(kid, alg)
		// an unknown kid usually means the realm rotated its keys: refetch once, but not more than every few seconds
		unknown := func() bool { return v.find(kid, alg) == nil && v.since(&v.triedAt) >= v.refetch }
		if jwk == nil && unknown() {
			if err := v.refreshKeepingOld(ctx, unknown); err != nil {
				return nil, err
			}
			jwk = v.find(kid, alg)
		}
	}
	if jwk == nil {
		return nil, invalid("token signed with an unknown key")
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return nil, invalid("token signed with an unusable key: %v", err)
	}
	return pub, nil
}

// refreshKeepingOld refetches the keys while still needed (another goroutine may have just done it); when that fails
// it keeps the keys already known and fails only when there are none.
func (v *Verifier) refreshKeepingOld(ctx context.Context, needed func() bool) error {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	if !needed() {
		return nil
	}
	keys, err := v.fetch(ctx)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.triedAt = v.now()
	if err != nil {
		if len(v.keys) == 0 {
			return invalid("cannot find the token's signing key: %v", err)
		}
		return nil
	}
	v.keys, v.fetchedAt = keys, v.triedAt
	return nil
}

func (v *Verifier) fetch(ctx context.Context) ([]JWK, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, v.jwksURL)
	}
	var set struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(set.Keys), []byte("[")) {
		return nil, errors.New("the JWKS has no keys")
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(set.Keys, &raw); err != nil {
		return nil, err
	}
	keys := make([]JWK, 0, len(raw))
	for _, r := range raw {
		var k JWK
		if json.Unmarshal(r, &k) == nil {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Bearer returns the token of an "Authorization: Bearer …" header value. Errors wrap ErrInvalidToken.
func Bearer(authorization string) (string, error) {
	if authorization == "" {
		return "", invalid("sign in: send Authorization: Bearer <token>")
	}
	scheme, token, _ := strings.Cut(authorization, " ")
	token = strings.TrimSpace(token)
	if !strings.EqualFold(scheme, "bearer") || token == "" {
		return "", invalid("expected Authorization: Bearer <token>")
	}
	return token, nil
}
