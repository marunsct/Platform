package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// EnableInternal turns on the /internal/v1 routes Keycloak's Matura extension calls (technical specification §6).
// They take a bearer token shared with Keycloak (MATURA_INTERNAL_TOKEN); without one they are not served.
func (s *Server) EnableInternal(token string) {
	if token == "" {
		return
	}
	want := sha256.Sum256([]byte(token))
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			sum := sha256.Sum256([]byte(got))
			if subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
				problem(w, http.StatusUnauthorized, "unauthenticated", "internal endpoints need the internal token")
				return
			}
			h(w, r)
		}
	}
	for _, rt := range s.internalHandlers() {
		s.internalRoutes = append(s.internalRoutes, route{rt.pattern, guard(rt.handler)})
	}
}

// internalHandlers lists the /internal/v1 routes, unguarded; EnableInternal serves them behind the token.
func (s *Server) internalHandlers() []route {
	return []route{
		{"POST /internal/v1/token-context", s.tokenContext},
		{"POST /internal/v1/mfa-policy", s.mfaPolicy},
		{"POST /internal/v1/sso-login", s.ssoLogin},
	}
}

// tokenContext answers the Keycloak mapper: the tenant, workspace, roles and permissions to put in a token.
// Refusals are 403 with the OAuth error code the mapper passes on (access_denied + error_description).
func (s *Server) tokenContext(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID        uuid.UUID `json:"user_id"`
		Email         string    `json:"email"`
		EmailVerified bool      `json:"email_verified"`
		Name          string    `json:"name"`
		Locale        string    `json:"locale"`
		ClientID      string    `json:"client_id"`
		Tenant        string    `json:"tenant"`
		Workspace     string    `json:"workspace"`
		// Keycloak session start and the last token issued in it, in Unix milliseconds (0: unknown)
		SessionStarted int64 `json:"session_started"`
		SessionLastUse int64 `json:"session_last_use"`
		// what an agent's client asked a token for (audience, resource or matura_app parameter)
		Audience string `json:"audience"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.UserID == uuid.Nil || in.ClientID == "" {
		problem(w, http.StatusBadRequest, "bad-request", "user_id and client_id are required")
		return
	}
	out, err := s.store.TokenContextFor(r.Context(), store.TokenRequest{
		User: store.UserProfile{ID: in.UserID, Email: in.Email, EmailVerified: in.EmailVerified, DisplayName: in.Name,
			Locale: in.Locale},
		ClientID: in.ClientID, Tenant: in.Tenant, Workspace: in.Workspace,
		SessionStarted: unixMilli(in.SessionStarted), SessionLastUse: unixMilli(in.SessionLastUse),
		App: in.Audience, APIAudience: s.apiAudience})
	if refusal(w, err) {
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.seen.Delete(in.UserID)
	writeJSON(w, http.StatusOK, out)
}

func unixMilli(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// refusal answers a *store.TokenRefusal the way the Keycloak extension expects (403 access_denied); ok is false
// when err is something else.
func refusal(w http.ResponseWriter, err error) bool {
	var ref *store.TokenRefusal
	if !errors.As(err, &ref) {
		return false
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"error": "access_denied", "error_description": ref.Code,
		"detail": ref.Msg})
	return true
}

// mfaPolicy answers the extension's MFA authenticator: must this user sign in with a second factor? It is required
// when any active tenant they actively belong to has require_mfa in its security policy.
func (s *Server) mfaPolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID uuid.UUID `json:"user_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.UserID == uuid.Nil {
		problem(w, http.StatusBadRequest, "bad-request", "user_id is required")
		return
	}
	tenants, err := s.store.TenantsRequiringMFA(r.Context(), in.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"required": len(tenants) > 0, "tenants": tenants})
}

// ssoLogin answers the extension's SSO authenticator for a sign-in through a tenant's identity provider: refused
// unless the asserted email is in a domain the tenant verified; with a user id, the user joins the tenant.
func (s *Server) ssoLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Alias  string    `json:"alias"`
		UserID uuid.UUID `json:"user_id"`
		Email  string    `json:"email"`
		Name   string    `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Alias == "" || in.Email == "" {
		problem(w, http.StatusBadRequest, "bad-request", "alias and email are required")
		return
	}
	out, err := s.store.SSOLogin(r.Context(), in.Alias, store.UserProfile{ID: in.UserID, Email: in.Email,
		DisplayName: in.Name})
	if refusal(w, err) {
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.UserID != uuid.Nil {
		s.seen.Delete(in.UserID)
	}
	writeJSON(w, http.StatusOK, out)
}
