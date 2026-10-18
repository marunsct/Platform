package matura

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type principalKey struct{}

// WithPrincipal returns a context carrying the principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal Middleware put in the request's context.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}

// problem writes an RFC 9457 problem+json answer.
func problem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "title": http.StatusText(status), "detail": detail})
}

func unauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="matura"`)
	problem(w, http.StatusUnauthorized, err.Error())
}

// Authenticate verifies the request's "Authorization: Bearer …" token. Errors wrap ErrInvalidToken.
func Authenticate(ctx context.Context, v *Verifier, r *http.Request) (*Principal, error) {
	tok, err := Bearer(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	return v.Verify(ctx, tok)
}

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*middleware)

type middleware struct {
	onPrincipal func(r *http.Request, p *Principal) error
}

// OnPrincipal runs after a token is verified, for example to write the just-in-time contract rows
// (Contract.ApplyPrincipal). An error answers 500.
func OnPrincipal(fn func(r *http.Request, p *Principal) error) MiddlewareOption {
	return func(m *middleware) { m.onPrincipal = fn }
}

// Middleware verifies the bearer token of every request and puts the principal in the request's context
// (PrincipalFrom). Requests without a valid token get 401 problem+json.
func Middleware(v *Verifier, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var m middleware
	for _, o := range opts {
		o(&m)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := Authenticate(r.Context(), v, r)
			if err != nil {
				unauthorized(w, err)
				return
			}
			if m.onPrincipal != nil {
				if err := m.onPrincipal(r, p); err != nil {
					problem(w, http.StatusInternalServerError, "cannot record the caller")
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

func require(check func(*Principal) error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				unauthorized(w, invalid("sign in: send Authorization: Bearer <token>"))
				return
			}
			if err := check(p); err != nil {
				problem(w, http.StatusForbidden, err.Error())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission answers 403 unless the principal (from Middleware) has every permission ("*" grants all).
func RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return require(func(p *Principal) error { return p.RequirePermission(permissions...) })
}

// RequireRole answers 403 unless the principal has one of this app's roles. Prefer RequirePermission.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return require(func(p *Principal) error { return p.RequireRole(roles...) })
}

// RequireTenantRole answers 403 unless the principal has one of the tenant roles (owner, admin, billing, member).
func RequireTenantRole(roles ...string) func(http.Handler) http.Handler {
	return require(func(p *Principal) error { return p.RequireTenantRole(roles...) })
}

// RequireTenant answers 403 unless the token is for a tenant.
func RequireTenant() func(http.Handler) http.Handler {
	return require(func(p *Principal) error { return p.RequireTenant() })
}

// WebhookHandler receives Matura's signed events (POST /matura/events): it verifies the signature, parses the
// CloudEvent and applies it in one transaction (contract §10.2). It answers 204 (applied, or already applied), 401
// (bad signature), 400 (not a Matura event) or 500 (database error, so Matura retries).
type WebhookHandler struct {
	Secrets   [][]byte   // the endpoint's signing secret (whsec_…); several during a rotation
	Contract  *Contract  // applies the event and runs its hooks
	DB        TxBeginner // each event is applied in one transaction
	Tolerance time.Duration
	Now       func() time.Time
	MaxBytes  int64                            // largest body accepted (default 1 MiB)
	OnError   func(r *http.Request, err error) // database and hook errors, for logging
	// Revocations, when set, get each matura.revocation.created event (the Verifier using them then refuses the
	// revoked tokens at once).
	Revocations *Revocations
}

// NewWebhookHandler returns a handler for one signing secret.
func NewWebhookHandler(secret string, contract *Contract, db TxBeginner) *WebhookHandler {
	return &WebhookHandler{Secrets: [][]byte{[]byte(secret)}, Contract: contract, DB: db}
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		problem(w, http.StatusMethodNotAllowed, "send events with POST")
		return
	}
	limit := h.MaxBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		problem(w, http.StatusRequestEntityTooLarge, "the event is too large")
		return
	}
	now, tol := time.Now(), h.Tolerance
	if h.Now != nil {
		now = h.Now()
	}
	if tol <= 0 {
		tol = SignatureTolerance
	}
	sigErr := errors.New("no signing secret configured")
	for _, s := range h.Secrets {
		if sigErr = verifySignature(s, r.Header.Get("Matura-Signature"), body, now, tol); sigErr == nil {
			break
		}
	}
	if sigErr != nil {
		problem(w, http.StatusUnauthorized, sigErr.Error())
		return
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil {
		problem(w, http.StatusBadRequest, "the body is not a CloudEvent")
		return
	}
	if h.Revocations != nil {
		h.Revocations.Apply(&e)
	}
	err = pgx.BeginFunc(r.Context(), h.DB, func(tx pgx.Tx) error {
		_, err := h.Contract.Apply(r.Context(), tx, &e)
		return err
	})
	switch {
	case errors.Is(err, ErrInvalidEvent):
		problem(w, http.StatusBadRequest, err.Error())
	case err != nil:
		if h.OnError != nil {
			h.OnError(r, err)
		}
		problem(w, http.StatusInternalServerError, "cannot apply the event; Matura will retry")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
