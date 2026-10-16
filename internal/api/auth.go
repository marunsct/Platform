package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Principal is the verified caller (technical specification §4).
type Principal struct {
	UserID        uuid.UUID
	Email         string
	EmailVerified bool
	Name          string
	Locale        string
	Operator      bool
}

// Authenticator turns a request into a Principal or an error that becomes 401.
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
}

var errNoCredentials = errors.New("sign in first: send Authorization: Bearer <access token>")

// DevAuthenticator trusts X-Matura-Dev-* headers. config.Validate only allows it with MATURA_ENV=development.
type DevAuthenticator struct{}

func (DevAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	raw := r.Header.Get("X-Matura-Dev-User")
	if raw == "" {
		return Principal{}, errNoCredentials
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return Principal{}, errors.New("X-Matura-Dev-User must be a UUID")
	}
	return Principal{
		UserID:        id,
		Email:         r.Header.Get("X-Matura-Dev-Email"),
		EmailVerified: true,
		Name:          r.Header.Get("X-Matura-Dev-Name"),
		Operator:      r.Header.Get("X-Matura-Dev-Operator") == "true",
	}, nil
}

// JWTAuthenticator verifies Keycloak access tokens: signature from the realm's JWKS, issuer, audience, expiry.
type JWTAuthenticator struct {
	Keyfunc      jwt.Keyfunc
	Issuer       string
	Audience     string
	OperatorRole string
}

type claims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Locale        string `json:"locale"`
	RealmAccess   struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

func (a JWTAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || token == "" {
		return Principal{}, errNoCredentials
	}
	var c claims
	_, err := jwt.ParseWithClaims(token, &c, a.Keyfunc,
		jwt.WithIssuer(a.Issuer), jwt.WithAudience(a.Audience), jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "PS256"}),
		jwt.WithLeeway(30*time.Second))
	if err != nil {
		return Principal{}, errors.New("invalid access token")
	}
	id, err := uuid.Parse(c.Subject)
	if err != nil {
		return Principal{}, errors.New("token subject is not a user id")
	}
	return Principal{
		UserID:        id,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
		Name:          c.Name,
		Locale:        c.Locale,
		Operator:      a.OperatorRole != "" && slices.Contains(c.RealmAccess.Roles, a.OperatorRole),
	}, nil
}

type ctxKey struct{}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

func principalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(ctxKey{}).(Principal)
	return p
}
