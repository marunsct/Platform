package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Principal is the verified caller (technical specification §4).
type Principal struct {
	UserID        uuid.UUID
	Email         string
	EmailVerified bool
	Name          string
	Locale        string
	Operator      bool
	AppID         uuid.UUID // set for app backends; UserID is then empty
	SessionID     string    // Keycloak SSO session (the token's sid), when known
	Kind          string    // of UserID: human (also when the token has no kind claim), service or agent
	Actor         *Actor    // set when an agent acts for UserID (the token's act claim, RFC 8693)
	IssuedAt      time.Time // the token's iat, for revocations (§21); zero when unknown
	TokenTenant   uuid.UUID // the token's tid, when it has one
}

// Actor is the agent a delegated token names in its act claim.
type Actor struct {
	ID       uuid.UUID
	Kind     string
	ClientID string
}

// actorOf reads an act claim; a malformed one is an error so a delegated token is never taken for the person's own.
func actorOf(act *actClaim) (*Actor, error) {
	if act == nil {
		return nil, nil
	}
	id, err := uuid.Parse(act.Sub)
	if err != nil {
		return nil, errors.New("token act.sub is not an agent id")
	}
	kind := act.Kind
	if kind != "service" {
		kind = "agent"
	}
	return &Actor{ID: id, Kind: kind, ClientID: act.ClientID}, nil
}

func kindOf(k string) string {
	if k == "service" || k == "agent" {
		return k
	}
	return "human"
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
	var act *actClaim
	if a := r.Header.Get("X-Matura-Dev-Act"); a != "" { // an agent acting for the user: its id
		act = &actClaim{Sub: a, Kind: "agent"}
	}
	actor, err := actorOf(act)
	if err != nil {
		return Principal{}, err
	}
	issued := time.Now()
	if v := r.Header.Get("X-Matura-Dev-Issued-At"); v != "" { // unix seconds, to test revocations
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Principal{}, errors.New("X-Matura-Dev-Issued-At must be unix seconds")
		}
		issued = time.Unix(sec, 0)
	}
	var tenant uuid.UUID
	if v := r.Header.Get("X-Matura-Dev-Tenant"); v != "" {
		if tenant, err = uuid.Parse(v); err != nil {
			return Principal{}, errors.New("X-Matura-Dev-Tenant must be a UUID")
		}
	}
	return Principal{
		IssuedAt:      issued,
		TokenTenant:   tenant,
		Actor:         actor,
		UserID:        id,
		Email:         r.Header.Get("X-Matura-Dev-Email"),
		EmailVerified: true,
		Name:          r.Header.Get("X-Matura-Dev-Name"),
		Operator:      r.Header.Get("X-Matura-Dev-Operator") == "true",
		SessionID:     r.Header.Get("X-Matura-Dev-Session"),
		Kind:          kindOf(r.Header.Get("X-Matura-Dev-Kind")),
	}, nil
}

// JWTAuthenticator verifies Keycloak access tokens: signature from the realm's JWKS, issuer, audience, expiry.
type JWTAuthenticator struct {
	Keyfunc      jwt.Keyfunc
	Issuer       string
	Audience     string
	OperatorRole string
}

type actClaim struct {
	Sub      string `json:"sub"`
	Kind     string `json:"kind"`
	ClientID string `json:"client_id"`
}

type claims struct {
	jwt.RegisteredClaims
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	Locale        string    `json:"locale"`
	SessionID     string    `json:"sid"`
	Kind          string    `json:"kind"`
	TenantID      string    `json:"tid"`
	Act           *actClaim `json:"act"`
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
	actor, err := actorOf(c.Act)
	if err != nil {
		return Principal{}, err
	}
	var issued time.Time
	if c.IssuedAt != nil {
		issued = c.IssuedAt.Time
	}
	tenant, _ := uuid.Parse(c.TenantID)
	return Principal{
		IssuedAt:      issued,
		TokenTenant:   tenant,
		Kind:          kindOf(c.Kind),
		Actor:         actor,
		UserID:        id,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
		Name:          c.Name,
		Locale:        c.Locale,
		Operator:      a.OperatorRole != "" && slices.Contains(c.RealmAccess.Roles, a.OperatorRole),
		SessionID:     c.SessionID,
	}, nil
}

type ctxKey struct{}
type appKey struct{}

func withApp(ctx context.Context, a store.App) context.Context {
	return context.WithValue(ctx, appKey{}, a)
}

func appFrom(ctx context.Context) store.App {
	a, _ := ctx.Value(appKey{}).(store.App)
	return a
}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

func principalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(ctxKey{}).(Principal)
	return p
}
