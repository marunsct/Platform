package store

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// agentTokenContext works out the claims of a token issued to an agent's Keycloak client (TS15). When the user is
// the agent's own service account (client credentials) the token is the agent's. When it is a person (standard
// token exchange, RFC 8693, or any other grant to the agent's client) the token is delegated: sub is the person,
// act names the agent, and roles and permissions are only those both of them have. The tenant is always the
// agent's; the app is the one the client asked for, else the only app the agent holds grants in.
func (s *Store) agentTokenContext(ctx context.Context, ag Agent, req TokenRequest) (TokenContext, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	if ag.Status != "active" {
		return TokenContext{}, refuse("agent_inactive", "this agent is deactivated")
	}
	if ag.ExpiresAt != nil && !now.Before(*ag.ExpiresAt) {
		return TokenContext{}, refuse("agent_expired", "this agent has expired")
	}
	delegated := req.User.ID != ag.ID
	var subject User
	if delegated {
		u, err := s.UpsertUser(ctx, req.User)
		if err != nil {
			return TokenContext{}, err
		}
		if u.Kind != "human" {
			return TokenContext{}, refuse("not_delegable", "an agent can act only for a person")
		}
		if u.Status != "active" {
			return TokenContext{}, refuse("user_inactive", "this account is deactivated")
		}
		subject = u
	}
	out := TokenContext{TenantRoles: []string{}, Roles: []string{}, Perms: []string{}, Versions: map[string]int64{}}
	var consented []string // permissions a consent narrows a delegated token to; nil: not narrowed
	err := s.tx(ctx, Scope{UserID: ag.ID, TenantID: ag.TenantID}, func(tx pgx.Tx) error {
		self, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1`, ag.ID))
		if err != nil {
			return err
		}
		if self.Status != "active" {
			return refuse("agent_inactive", "this agent is deactivated")
		}
		if !delegated {
			subject = self
		}
		t, err := scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1`, ag.TenantID))
		if err != nil {
			return err
		}
		if err := tenantRefusal(t); err != nil {
			return err
		}
		am, err := getMember(ctx, tx, t.ID, ag.ID, false)
		if err != nil || am.Status != "active" {
			return refuse("agent_inactive", "this agent is not an active member of its organisation")
		}
		m := am
		if delegated {
			um, err := getMember(ctx, tx, t.ID, subject.ID, false)
			if err == ErrNotFound || (err == nil && um.Status != "active") {
				return refuse("not_a_member", "you are not a member of this agent's organisation")
			}
			if err != nil {
				return err
			}
			if err := checkSessionLimits(ctx, tx, t.ID, req); err != nil {
				return err
			}
			m = um
			out.Act = &TokenActor{Sub: ag.ID, Kind: ag.Kind, ClientID: ag.ClientID}
			if ag.Consent == "required" { // §20.5: the person must have approved this agent
				c, err := activeConsent(ctx, tx, ag.ID, subject.ID, now)
				if err == ErrNotFound {
					return refuse("consent_required", "approve "+ag.Name+" to act for you first (consent screen: "+
						"/agents/consent?client_id="+ag.ClientID+")")
				}
				if err != nil {
					return err
				}
				consented = c.Permissions
			}
		}
		out.TenantID, out.TenantSlug, out.Kind = &t.ID, t.Slug, subject.Kind
		out.Versions["u"], out.Versions["m"], out.Versions["t"] = subject.Version, m.Version, t.Version
		if m.TenantRole == am.TenantRole {
			out.TenantRoles = []string{am.TenantRole}
		}
		if req.App != "" && req.App == req.APIAudience { // maturad's own API: tenant claims, no app roles
			out.Audience = req.APIAudience
			return nil
		}
		app, err := agentApp(ctx, tx, ag, req.App)
		if err != nil {
			return err
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_app WHERE tenant_id = $1 AND app_id = $2
			AND status = 'enabled')`, t.ID, app.ID).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return refuse("app_not_enabled", "this organisation has not enabled "+app.Name)
		}
		wid, err := chooseWorkspace(ctx, tx, t.ID, req.Workspace)
		if err != nil {
			return err
		}
		roles, err := rolesFor(ctx, tx, app, t.ID, ag.ID, am.TenantRole, wid)
		if err != nil {
			return err
		}
		perms, err := permsOf(ctx, tx, app.ID, roles)
		if err != nil {
			return err
		}
		if delegated {
			userRoles, err := rolesFor(ctx, tx, app, t.ID, subject.ID, m.TenantRole, wid)
			if err != nil {
				return err
			}
			userPerms, err := permsOf(ctx, tx, app.ID, userRoles)
			if err != nil {
				return err
			}
			roles = slices.DeleteFunc(roles, func(r string) bool { return !slices.Contains(userRoles, r) })
			perms = IntersectPerms(perms, userPerms)
			if consented != nil {
				// only what the person consented to; no roles, since an app could read more permissions from them
				perms, roles = IntersectPerms(perms, consented), []string{}
			}
		}
		var mode *string
		if err := tx.QueryRow(ctx, `SELECT mode FROM placement WHERE tenant_id = $1 AND app_id = $2`, t.ID, app.ID).
			Scan(&mode); err != nil && mapErr(err) != ErrNotFound {
			return err
		}
		out.Roles, out.Audience = roles, app.ClientID
		if wid != uuid.Nil {
			out.WorkspaceID = &wid
		}
		if len(perms) > MaxPermsInToken && consented == nil {
			out.PermsRef, out.Perms = "matura_app_role", nil
		} else {
			out.Perms = perms
		}
		if mode != nil {
			out.PlaceMode = *mode
		}
		return nil
	})
	return out, err
}

// agentApp resolves the app an agent asked a token for: by client id or by a manifest auth resource; with nothing
// asked, the only app it holds grants in.
func agentApp(ctx context.Context, tx pgx.Tx, ag Agent, want string) (App, error) {
	if want != "" {
		app, err := scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app WHERE status = 'active'
			AND (client_id = $1 OR manifest->'auth'->'resources' ? $1) ORDER BY client_id = $1 DESC LIMIT 1`, want))
		if err == ErrNotFound {
			return app, refuse("unknown_audience", "no app answers to "+want)
		}
		return app, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT a.client_id FROM role_grant g JOIN app a ON a.id = g.app_id
		WHERE g.tenant_id = $1 AND g.subject_type = 'user' AND g.subject_id = $2 AND g.status = 'active'
		AND a.status = 'active'`, ag.TenantID, ag.ID)
	if err != nil {
		return App{}, err
	}
	apps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return App{}, err
	}
	if len(apps) != 1 {
		return App{}, refuse("audience_required", "name the app the token is for: audience=<app client id>")
	}
	return agentApp(ctx, tx, ag, apps[0])
}

// IntersectPerms returns the permissions both lists allow, sorted: what a delegated token may do. "*" allows
// everything the other side has.
func IntersectPerms(a, b []string) []string {
	switch {
	case slices.Contains(a, "*") && slices.Contains(b, "*"):
		return []string{"*"}
	case slices.Contains(a, "*"):
		return slices.Sorted(slices.Values(b))
	case slices.Contains(b, "*"):
		return slices.Sorted(slices.Values(a))
	}
	out := []string{}
	for _, p := range a {
		if slices.Contains(b, p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// tenantRefusal refuses tokens for a tenant that is not active (TN-3).
func tenantRefusal(t Tenant) error {
	switch t.Status {
	case "active":
		return nil
	case "suspended":
		return refuse("tenant_suspended", "this organisation is suspended")
	case "pending_deletion":
		return refuse("tenant_pending_deletion", "this organisation is scheduled for deletion")
	}
	return refuse("tenant_inactive", "this organisation is not available")
}
