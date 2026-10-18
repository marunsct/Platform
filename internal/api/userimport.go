package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/store"
)

// User import (TS27, technical specification §5.4): operators move people from another identity system (Auth0,
// Clerk, Keycloak; `matura import` converts their exports) into Matura with their organisations and roles.

type importTenant struct {
	Slug       string              `json:"slug"`
	Name       string              `json:"name"`
	TenantRole string              `json:"tenant_role"` // owner, admin, billing or member (default)
	AppRoles   []store.InvitedRole `json:"app_roles"`
}

type importUser struct {
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	FirstName     string         `json:"first_name"`
	LastName      string         `json:"last_name"`
	Disabled      bool           `json:"disabled"`
	Source        string         `json:"source"`      // auth0, clerk, keycloak…
	ExternalID    string         `json:"external_id"` // the id there, kept as a Keycloak attribute
	Tenants       []importTenant `json:"tenants"`
}

type importResult struct {
	Email   string   `json:"email"`
	Status  string   `json:"status"` // created, existing or error
	UserID  string   `json:"user_id,omitempty"`
	Error   string   `json:"error,omitempty"`
	Joined  []string `json:"joined,omitempty"` // tenant slugs
	Created []string `json:"created_tenants,omitempty"`
	Issues  []string `json:"issues,omitempty"` // memberships or roles that could not be made
}

// POST /admin/v1/users:import {users, send_password_email}: accounts are created at Keycloak (or found by email),
// then tenants are created for their owners, then everyone joins with their tenant and app roles. Idempotent:
// running it again finds the accounts and memberships it made.
func (s *Server) importUsers(w http.ResponseWriter, r *http.Request) {
	if !principalFrom(r.Context()).Operator {
		problem(w, http.StatusForbidden, "forbidden", "operators only")
		return
	}
	if !s.needKeycloak(w) {
		return
	}
	var in struct {
		Users             []importUser `json:"users"`
		SendPasswordEmail bool         `json:"send_password_email"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Users) == 0 || len(in.Users) > 1000 {
		problem(w, http.StatusUnprocessableEntity, "invalid", "send 1 to 1000 users per request")
		return
	}
	ctx, op := r.Context(), store.Scope{Operator: true}
	results := make([]importResult, len(in.Users))
	ids := make([]uuid.UUID, len(in.Users))

	// 1. accounts
	for i, u := range in.Users {
		res := &results[i]
		res.Email = strings.TrimSpace(u.Email)
		if !strings.Contains(res.Email, "@") {
			res.Status, res.Error = "error", "email is required"
			continue
		}
		acct, err := s.kc.AccountByEmail(ctx, res.Email)
		switch {
		case err == nil:
			res.Status = "existing"
		case errors.Is(err, keycloak.ErrNotFound):
			attrs := map[string][]string{}
			if u.Source != "" {
				attrs["matura_import_source"] = []string{u.Source}
			}
			if u.ExternalID != "" {
				attrs["matura_import_id"] = []string{u.ExternalID}
			}
			id, err := s.kc.CreateAccount(ctx, keycloak.Account{Username: strings.ToLower(res.Email), Email: res.Email,
				EmailVerified: u.EmailVerified, FirstName: u.FirstName, LastName: u.LastName, Enabled: !u.Disabled,
				Attributes: attrs, RequiredActions: []string{"UPDATE_PASSWORD"}})
			if err != nil {
				res.Status, res.Error = "error", "identity provider: "+err.Error()
				continue
			}
			acct = keycloak.Account{ID: id}
			res.Status = "created"
			if in.SendPasswordEmail && !u.Disabled {
				if err := s.kc.ExecuteActionsEmail(ctx, id, []string{"UPDATE_PASSWORD"}); err != nil {
					res.Issues = append(res.Issues, "password email not sent: "+err.Error())
				}
			}
		default:
			res.Status, res.Error = "error", "identity provider: "+err.Error()
			continue
		}
		uid, err := uuid.Parse(acct.ID)
		if err != nil {
			res.Status, res.Error = "error", "identity provider returned an id that is not a UUID"
			continue
		}
		name := strings.TrimSpace(u.FirstName + " " + u.LastName)
		if _, err := s.store.UpsertUser(ctx, store.UserProfile{ID: uid, Email: res.Email, EmailVerified: u.EmailVerified,
			DisplayName: name}); err != nil {
			res.Status, res.Error = "error", err.Error()
			continue
		}
		if u.Disabled {
			if _, err := s.store.SetUserStatus(ctx, op, uid, "deactivated"); err != nil {
				res.Issues = append(res.Issues, "not deactivated: "+err.Error())
			}
		}
		ids[i], res.UserID = uid, uid.String()
	}

	// 2. tenants that do not exist yet, made by their first owner in the request
	tenants := map[string]uuid.UUID{}
	for i, u := range in.Users {
		if ids[i] == uuid.Nil {
			continue
		}
		for _, t := range u.Tenants {
			if _, ok := tenants[t.Slug]; ok {
				continue
			}
			if got, err := s.store.TenantBySlug(ctx, t.Slug); err == nil {
				tenants[t.Slug] = got.ID
				continue
			}
			if t.TenantRole != "owner" {
				continue
			}
			name := t.Name
			if name == "" {
				name = t.Slug
			}
			created, err := s.store.CreateTenant(ctx, op, store.NewTenant{Slug: t.Slug, Name: name}, ids[i])
			if err != nil {
				results[i].Issues = append(results[i].Issues, t.Slug+": "+err.Error())
				continue
			}
			tenants[t.Slug] = created.ID
			results[i].Created = append(results[i].Created, t.Slug)
		}
	}

	// 3. memberships and app roles
	for i, u := range in.Users {
		if ids[i] == uuid.Nil {
			continue
		}
		res := &results[i]
		for _, t := range u.Tenants {
			tid, ok := tenants[t.Slug]
			if !ok {
				res.Issues = append(res.Issues, t.Slug+": no such organisation, and no owner of it in this import")
				continue
			}
			role := t.TenantRole
			if role == "" {
				role = "member"
			}
			_, err := s.store.AddMember(ctx, op, tid, ids[i], role)
			switch {
			case err == nil, errors.Is(err, store.ErrConflict): // already a member (an owner who made it, or a rerun)
			default:
				res.Issues = append(res.Issues, t.Slug+": "+errorMessage(err))
				continue
			}
			res.Joined = append(res.Joined, t.Slug)
			for _, ar := range t.AppRoles {
				if _, err := s.store.EnableApp(ctx, op, tid, ar.App); err != nil && !errors.Is(err, store.ErrConflict) {
					res.Issues = append(res.Issues, t.Slug+"/"+ar.App+": "+errorMessage(err))
					continue
				}
				if _, err := s.store.CreateGrant(ctx, op, tid, store.NewGrant{App: ar.App, UserID: ids[i], Role: ar.Role,
					WorkspaceID: ar.WorkspaceID}); err != nil && !errors.Is(err, store.ErrConflict) {
					res.Issues = append(res.Issues, t.Slug+"/"+ar.App+":"+ar.Role+": "+errorMessage(err))
				}
			}
		}
	}
	counts := map[string]int{}
	for _, res := range results {
		counts[res.Status]++
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": counts["created"], "existing": counts["existing"],
		"failed": counts["error"], "results": results})
}

func errorMessage(err error) string {
	var inv *store.InvalidError
	var lim *store.LimitError
	switch {
	case errors.As(err, &inv):
		return inv.Msg
	case errors.As(err, &lim):
		return lim.Msg
	}
	return err.Error()
}
