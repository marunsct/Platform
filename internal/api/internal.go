package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

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
	return []route{{"POST /internal/v1/token-context", s.tokenContext}}
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
		ClientID: in.ClientID, Tenant: in.Tenant, Workspace: in.Workspace})
	var refusal *store.TokenRefusal
	if errors.As(err, &refusal) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "access_denied", "error_description": refusal.Code,
			"detail": refusal.Msg})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.seen.Delete(in.UserID)
	writeJSON(w, http.StatusOK, out)
}
