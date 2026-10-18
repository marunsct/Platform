package api

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
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
		s.createTempPasswordInvitation(w, r, tid, sc, in.Email, in.TenantRole, in.AppRoles, in.DeliverTo)
		return
	default:
		problem(w, http.StatusUnprocessableEntity, "invalid", "delivery must be link or temp_password")
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

// tempPassword is 16 characters from an alphabet without look-alikes (about 90 bits).
func tempPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, 0, 16)
	buf := make([]byte, 32)
	limit := 256 - 256%len(alphabet) // reject the bytes that would bias the choice
	for len(out) < 16 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, c := range buf {
			if int(c) < limit && len(out) < 16 {
				out = append(out, alphabet[int(c)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}

// createTempPasswordInvitation onboards someone with a temporary password (TS6, technical specification §5.1):
// maturad creates their account with a one-time password Keycloak makes them change at the first sign-in, and the
// invitation is accepted at that sign-in. Only for addresses without an account (409 otherwise: send a link). The
// password is in this response only, and in an email to deliver_to when one is given.
func (s *Server) createTempPasswordInvitation(w http.ResponseWriter, r *http.Request, tid uuid.UUID, sc store.Scope,
	email, role string, appRoles []store.InvitedRole, deliverTo string) {
	if !s.needKeycloak(w) {
		return
	}
	email = strings.TrimSpace(email)
	if _, err := s.kc.AccountByEmail(r.Context(), email); err == nil {
		problem(w, http.StatusConflict, "account-exists", email+" already has an account; invite it with a link instead")
		return
	} else if !errors.Is(err, keycloak.ErrNotFound) {
		s.kcFail(w, r, err)
		return
	}
	password, err := tempPassword()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	verified, err := s.store.IsVerifiedDomain(r.Context(), tid, email)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actions := []string{"UPDATE_PASSWORD"}
	if !verified {
		actions = append(actions, "VERIFY_EMAIL")
	}
	id, err := s.kc.CreateAccount(r.Context(), keycloak.Account{Username: strings.ToLower(email), Email: email,
		EmailVerified: verified, Enabled: true, RequiredActions: actions,
		Credentials: []keycloak.PasswordCredential{{Type: "password", Value: password, Temporary: true}}})
	if err != nil {
		s.kcFail(w, r, err)
		return
	}
	account, err := uuid.Parse(id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	token, err := newInvitationToken() // not sent; the invitation is accepted by its account's first sign-in
	if err != nil {
		s.fail(w, r, err)
		return
	}
	compose := func(inv store.Invitation) store.Email {
		if inv.DeliverTo == nil {
			return store.Email{}
		}
		return store.Email{To: *inv.DeliverTo, Subject: "Sign-in details for " + inv.Email,
			Body: "Hello,\n\nAn account was created for " + inv.Email + " on " + s.invites.Product + ".\n\n" +
				"Sign in at " + strings.TrimRight(s.invites.PublicURL, "/") + "/portal/ with:\n" +
				"  email: " + inv.Email + "\n  temporary password: " + password + "\n\n" +
				"The password must be changed at the first sign-in and works until " +
				inv.ExpiresAt.UTC().Format("2 January 2006 15:04 MST") + ". Pass it on in person if you can.\n"}
	}
	inv, err := s.store.CreateInvitation(r.Context(), sc, tid, store.NewInvitation{Email: email, TenantRole: role,
		AppRoles: appRoles, DeliverTo: deliverTo, InvitedBy: principalFrom(r.Context()).UserID, Token: token,
		Delivery: "temp_password", AccountID: account, TTL: store.TempPasswordTTL}, compose)
	if err != nil {
		_ = s.kc.DeleteUser(r.Context(), account) // no account is left behind for a refused invitation
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"invitation": inv, "temporary_password": password,
		"account_id": account, "expires_at": inv.ExpiresAt})
}

// POST /v1/tenants/{tid}/invitations:bulk with a CSV body (text/csv): header email[,tenant_role][,app_roles]
// [,deliver_to], app_roles as app:role separated by ";". Up to 500 rows; each becomes a link invitation, or a
// per-row error, so one bad row does not stop the rest.
func (s *Server) bulkInvitations(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathUUID(w, r, "tid")
	if !ok {
		return
	}
	sc, m, err := s.tenantAccess(r, tid, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rd := csv.NewReader(http.MaxBytesReader(w, r.Body, 1<<20))
	rd.TrimLeadingSpace, rd.FieldsPerRecord = true, -1
	rows, err := rd.ReadAll()
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "the body is not CSV (at most 1 MB): "+err.Error())
		return
	}
	if len(rows) < 2 {
		problem(w, http.StatusUnprocessableEntity, "invalid", "send a header row (email,tenant_role,app_roles,deliver_to) and at least one row")
		return
	}
	if len(rows) > 501 {
		problem(w, http.StatusUnprocessableEntity, "invalid", "at most 500 rows per request")
		return
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	if _, ok := col["email"]; !ok {
		problem(w, http.StatusUnprocessableEntity, "invalid", "the header needs an email column")
		return
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	type result struct {
		Row       int    `json:"row"`
		Email     string `json:"email"`
		Status    string `json:"status"` // invited or error
		Error     string `json:"error,omitempty"`
		ID        string `json:"id,omitempty"`
		AcceptURL string `json:"accept_url,omitempty"`
	}
	results := make([]result, 0, len(rows)-1)
	invited := 0
	for i, row := range rows[1:] {
		res := result{Row: i + 2, Email: get(row, "email")}
		role := get(row, "tenant_role")
		var apps []store.InvitedRole
		for _, pair := range strings.Split(get(row, "app_roles"), ";") {
			if pair = strings.TrimSpace(pair); pair == "" {
				continue
			}
			app, rl, ok := strings.Cut(pair, ":")
			if !ok {
				res.Status, res.Error = "error", "app_roles must be app:role, separated by ;"
				break
			}
			apps = append(apps, store.InvitedRole{App: strings.TrimSpace(app), Role: strings.TrimSpace(rl)})
		}
		if res.Status == "" && role == "owner" && !sc.Operator && m.TenantRole != "owner" {
			res.Status, res.Error = "error", "only owners invite owners"
		}
		if res.Status == "" {
			token, err := newInvitationToken()
			if err != nil {
				s.fail(w, r, err)
				return
			}
			inv, err := s.store.CreateInvitation(r.Context(), sc, tid, store.NewInvitation{Email: res.Email,
				TenantRole: role, AppRoles: apps, DeliverTo: get(row, "deliver_to"),
				InvitedBy: principalFrom(r.Context()).UserID, Token: token}, s.compose(r, tid, token))
			var inv2 *store.InvalidError
			switch {
			case err == nil:
				res.Status, res.ID, res.AcceptURL = "invited", inv.ID.String(), s.acceptLink(token)
				invited++
			case errors.As(err, &inv2):
				res.Status, res.Error = "error", inv2.Msg
			case errors.Is(err, store.ErrConflict):
				res.Status, res.Error = "error", "already a member"
			default:
				s.fail(w, r, err)
				return
			}
		}
		results = append(results, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"invited": invited, "failed": len(results) - invited, "results": results})
}
