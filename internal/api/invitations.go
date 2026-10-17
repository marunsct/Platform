package api

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// Invitations configures invitation links and the accept page (TS6).
type Invitations struct {
	// AcceptURL is the page an invitation link opens; the token is added as ?token=. Default: maturad's own page,
	// <PublicURL>/invitations/accept.
	AcceptURL string
	PublicURL string // where people reach maturad, for the default AcceptURL
	Issuer    string // Keycloak realm URL the accept page signs in with
	ClientID  string // public client the accept page uses (PKCE)
	Product   string // name shown in emails; default "Matura"
}

// SetInvitations configures invitation links and the accept page.
func (s *Server) SetInvitations(c Invitations) {
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.AcceptURL == "" {
		c.AcceptURL = c.PublicURL + "/invitations/accept"
	}
	if c.Product == "" {
		c.Product = "Matura"
	}
	s.invites = c
}

func (s *Server) acceptLink(token string) string {
	return s.invites.AcceptURL + "?token=" + url.QueryEscape(token)
}

func newInvitationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// compose writes the invitation email in the inviter's words.
func (s *Server) compose(r *http.Request, tid uuid.UUID, token string) store.Compose {
	p := principalFrom(r.Context())
	inviter := p.Name
	if inviter == "" {
		inviter = p.Email
	}
	if inviter == "" {
		inviter = "Your administrator"
	}
	tenant := "a team"
	if t, err := s.store.GetTenant(r.Context(), store.Scope{Operator: true}, tid); err == nil {
		tenant = t.Name
	}
	return func(inv store.Invitation) store.Email {
		return store.Email{
			To:      inv.Recipient(),
			Subject: inviter + " invited you to " + tenant,
			Body: "Hello,\n\n" +
				inviter + " invited " + inv.Email + " to join " + tenant + " on " + s.invites.Product + ".\n\n" +
				"Accept the invitation:\n" + s.acceptLink(token) + "\n\n" +
				"Sign in, or create an account, with " + inv.Email + ". The link works until " +
				inv.ExpiresAt.UTC().Format("2 January 2006 15:04 MST") + ".\n\n" +
				"If you did not expect this invitation, you can ignore this email.\n",
		}
	}
}

type invitationOut struct {
	store.Invitation
	AcceptURL string `json:"accept_url,omitempty"` // only when the link was just made; it is not stored
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	var in struct {
		Email      string              `json:"email"`
		TenantRole string              `json:"tenant_role"`
		AppRoles   []store.InvitedRole `json:"app_roles"`
		Delivery   string              `json:"delivery"`
		DeliverTo  string              `json:"deliver_to"`
	}
	if !decode(w, r, &in) {
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.TenantRole == "owner" && !sc.Operator && m.TenantRole != "owner" {
		s.fail(w, r, errForbidden)
		return
	}
	switch in.Delivery {
	case "", "link":
	case "temp_password":
		problem(w, http.StatusUnprocessableEntity, "invalid", "temporary passwords are not available yet; use delivery link")
		return
	default:
		problem(w, http.StatusUnprocessableEntity, "invalid", "delivery must be link")
		return
	}
	token, err := newInvitationToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	inv, err := s.store.CreateInvitation(r.Context(), sc, tid, store.NewInvitation{Email: in.Email,
		TenantRole: in.TenantRole, AppRoles: in.AppRoles, DeliverTo: in.DeliverTo,
		InvitedBy: principalFrom(r.Context()).UserID, Token: token}, s.compose(r, tid, token))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, invitationOut{inv, s.acceptLink(token)})
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.store.ListInvitations(r.Context(), sc, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(out)})
}

// invitationAction handles POST …/invitations/{id}:resend.
func (s *Server) invitationAction(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	raw, found := strings.CutSuffix(r.PathValue("id"), ":resend")
	id, err := uuid.Parse(raw)
	if !found || err != nil {
		problem(w, http.StatusNotFound, "not-found", "not found")
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	token, err := newInvitationToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	inv, err := s.store.ResendInvitation(r.Context(), sc, tid, id, token, s.compose(r, tid, token))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, invitationOut{inv, s.acceptLink(token)})
}

func (s *Server) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sc, _, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.store.RevokeInvitation(r.Context(), sc, tid, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// acceptInvitation is POST /v1/invitations:accept, called by the signed-in invitee.
func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	if p.UserID == uuid.Nil {
		problem(w, http.StatusForbidden, "forbidden", "sign in as the invited person")
		return
	}
	inv, m, err := s.store.AcceptInvitation(r.Context(), p.UserID, p.Email, in.Token)
	switch {
	case errors.Is(err, store.ErrInvitationGone):
		problem(w, http.StatusGone, "invitation-gone", err.Error())
	case errors.Is(err, store.ErrWrongInvitee):
		problem(w, http.StatusForbidden, "wrong-invitee", err.Error())
	case err != nil:
		s.fail(w, r, err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"invitation": inv, "membership": m})
	}
}

// previewInvitation is GET /invitations/preview?token=…, unauthenticated: the token is the credential.
func (s *Server) previewInvitation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	out, err := s.store.PreviewInvitation(r.Context(), r.URL.Query().Get("token"))
	if errors.Is(err, store.ErrInvitationGone) {
		problem(w, http.StatusGone, "invitation-gone", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

//go:embed accept.html
var acceptHTML string

var acceptPage = template.Must(template.New("accept").Parse(acceptHTML))

// acceptPageHandler serves GET /invitations/accept: it signs the invitee in with Keycloak (authorization code with
// PKCE, as a public client) and accepts the invitation with the resulting token.
func (s *Server) acceptPageHandler(w http.ResponseWriter, r *http.Request) {
	nonce, err := newInvitationToken()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cfg, _ := json.Marshal(map[string]string{"issuer": s.invites.Issuer, "client_id": s.invites.ClientID,
		"product": s.invites.Product})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer") // the URL carries the token
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
		"connect-src 'self' "+originOf(s.invites.Issuer)+"; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	_ = acceptPage.Execute(w, map[string]any{"Config": template.JS(cfg), "Product": s.invites.Product,
		"Nonce": nonce})
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
