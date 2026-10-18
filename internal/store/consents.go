package store

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// Consent is a person's approval for an agent to act on their behalf (technical specification §20.5). Permissions
// nil means everything both of them may do; otherwise the delegated token carries only these (and no roles).
type Consent struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	AgentID     uuid.UUID  `json:"agent_id"`
	UserID      uuid.UUID  `json:"user_id"`
	Permissions []string   `json:"permissions"`
	Status      string     `json:"status"` // active or withdrawn
	GrantedAt   time.Time  `json:"granted_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	WithdrawnAt *time.Time `json:"withdrawn_at"`
	WithdrawnBy *uuid.UUID `json:"withdrawn_by"`
	Version     int64      `json:"version"`
	// for listings
	AgentName   string `json:"agent_name,omitempty"`
	AgentClient string `json:"agent_client_id,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"`
}

const consentCols = `c.id, c.tenant_id, c.agent_id, c.user_id, c.permissions, c.status, c.granted_at, c.expires_at,
	c.withdrawn_at, c.withdrawn_by, c.version, a.name, a.client_id, t.name`

const consentFrom = ` FROM agent_consent c JOIN agent a ON a.id = c.agent_id JOIN tenant t ON t.id = c.tenant_id`

func scanConsent(row pgx.Row) (Consent, error) {
	var c Consent
	err := row.Scan(&c.ID, &c.TenantID, &c.AgentID, &c.UserID, &c.Permissions, &c.Status, &c.GrantedAt,
		&c.ExpiresAt, &c.WithdrawnAt, &c.WithdrawnBy, &c.Version, &c.AgentName, &c.AgentClient, &c.TenantName)
	return c, err
}

func collectConsents(rows pgx.Rows, err error) ([]Consent, error) {
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Consent, error) { return scanConsent(r) })
	if out == nil {
		out = []Consent{}
	}
	return out, err
}

// ConsentRequest is what the consent screen shows a person: the agent, its organisation, and per app what it could
// do for them (the permissions both hold), with their current consent if any.
type ConsentRequest struct {
	Agent struct {
		ID          uuid.UUID `json:"id"`
		ClientID    string    `json:"client_id"`
		Kind        string    `json:"kind"`
		Name        string    `json:"name"`
		Description *string   `json:"description"`
		Owner       *string   `json:"owner"`
		Consent     string    `json:"consent"`
	} `json:"agent"`
	TenantID   uuid.UUID           `json:"tenant_id"`
	TenantName string              `json:"tenant_name"`
	Apps       []ConsentAppRequest `json:"apps"`
	Current    *Consent            `json:"current"`
}

// ConsentAppRequest is one app the agent holds roles in, and what it could do there for the person.
type ConsentAppRequest struct {
	App         string   `json:"app"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// agentForPerson finds an agent by client id and checks the person is an active member of its tenant (otherwise
// ErrNotFound, so the agent's existence is not revealed to outsiders).
func (s *Store) agentForPerson(ctx context.Context, clientID string, userID uuid.UUID) (Agent, error) {
	var ag Agent
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var err error
		if ag, err = agentByClient(ctx, tx, clientID); err != nil {
			return err
		}
		if ag.Status == "deleted" {
			return ErrNotFound
		}
		m, err := getMember(ctx, tx, ag.TenantID, userID, false)
		if err != nil || m.Status != "active" || m.Kind != "human" {
			return ErrNotFound
		}
		return nil
	})
	return ag, err
}

// ConsentRequestFor builds the consent screen for a person and the agent with this client id.
func (s *Store) ConsentRequestFor(ctx context.Context, clientID string, userID uuid.UUID) (ConsentRequest, error) {
	var out ConsentRequest
	ag, err := s.agentForPerson(ctx, clientID, userID)
	if err != nil {
		return out, err
	}
	err = s.tx(ctx, Scope{TenantID: ag.TenantID, UserID: userID}, func(tx pgx.Tx) error {
		out.Agent.ID, out.Agent.ClientID, out.Agent.Kind, out.Agent.Name = ag.ID, ag.ClientID, ag.Kind, ag.Name
		out.Agent.Description, out.Agent.Consent, out.TenantID = ag.Description, ag.Consent, ag.TenantID
		if err := tx.QueryRow(ctx, `SELECT name FROM tenant WHERE id = $1`, ag.TenantID).Scan(&out.TenantName); err != nil {
			return err
		}
		if ag.OwnerID != nil {
			var owner *string
			_ = tx.QueryRow(ctx, `SELECT coalesce(display_name, email) FROM app_user WHERE id = $1`, *ag.OwnerID).Scan(&owner)
			out.Agent.Owner = owner
		}
		am, err := getMember(ctx, tx, ag.TenantID, ag.ID, false)
		if err != nil {
			return err
		}
		um, err := getMember(ctx, tx, ag.TenantID, userID, false)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT a.client_id FROM role_grant g JOIN app a ON a.id = g.app_id
			JOIN tenant_app ta ON ta.app_id = a.id AND ta.tenant_id = g.tenant_id AND ta.status = 'enabled'
			WHERE g.tenant_id = $1 AND g.subject_type = 'user' AND g.subject_id = $2 AND g.status = 'active'
			AND a.status = 'active' ORDER BY a.client_id`, ag.TenantID, ag.ID)
		if err != nil {
			return err
		}
		apps, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		out.Apps = []ConsentAppRequest{}
		for _, slug := range apps {
			app, err := scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app WHERE client_id = $1`, slug))
			if err != nil {
				return err
			}
			agentRoles, err := rolesFor(ctx, tx, app, ag.TenantID, ag.ID, am.TenantRole, uuid.Nil)
			if err != nil {
				return err
			}
			userRoles, err := rolesFor(ctx, tx, app, ag.TenantID, userID, um.TenantRole, uuid.Nil)
			if err != nil {
				return err
			}
			ap, err := permsOf(ctx, tx, app.ID, agentRoles)
			if err != nil {
				return err
			}
			up, err := permsOf(ctx, tx, app.ID, userRoles)
			if err != nil {
				return err
			}
			out.Apps = append(out.Apps, ConsentAppRequest{App: app.ClientID, Name: app.Name, Permissions: IntersectPerms(ap, up)})
		}
		cur, err := activeConsent(ctx, tx, ag.ID, userID, time.Now())
		if err == nil {
			out.Current = &cur
		} else if err != ErrNotFound {
			return err
		}
		return nil
	})
	return out, err
}

// activeConsent is the person's consent for the agent that is active and not expired at now.
func activeConsent(ctx context.Context, tx pgx.Tx, agentID, userID uuid.UUID, now time.Time) (Consent, error) {
	c, err := scanConsent(tx.QueryRow(ctx, `SELECT `+consentCols+consentFrom+`
		WHERE c.agent_id = $1 AND c.user_id = $2 AND c.status = 'active' AND (c.expires_at IS NULL OR c.expires_at > $3)`,
		agentID, userID, now))
	return c, mapErr(err)
}

// GrantConsent records (or replaces) the person's consent for the agent with this client id. permissions nil
// allows everything both may do; a list narrows it (each must be something the agent could do for them).
func (s *Store) GrantConsent(ctx context.Context, clientID string, userID uuid.UUID, permissions []string, expiresAt *time.Time) (Consent, error) {
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return Consent{}, invalid("expires_at must be in the future")
	}
	req, err := s.ConsentRequestFor(ctx, clientID, userID)
	if err != nil {
		return Consent{}, err
	}
	if permissions != nil {
		possible := []string{}
		for _, a := range req.Apps {
			possible = append(possible, a.Permissions...)
		}
		for _, p := range permissions {
			if !slices.Contains(possible, p) && !slices.Contains(possible, "*") {
				return Consent{}, invalid("the agent cannot do %q for you, so it cannot be consented to", p)
			}
		}
		permissions = slices.Compact(slices.Sorted(slices.Values(permissions)))
		if len(permissions) == 0 {
			return Consent{}, invalid("consent to at least one permission, or omit permissions to allow all")
		}
	}
	var out Consent
	err = s.tx(ctx, Scope{TenantID: req.TenantID, UserID: userID}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE agent_consent SET status = 'withdrawn', withdrawn_at = now(), withdrawn_by = $3
			WHERE agent_id = $1 AND user_id = $2 AND status = 'active'`, req.Agent.ID, userID, userID); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		id := ids.New()
		if _, err := tx.Exec(ctx, `INSERT INTO agent_consent (id, tenant_id, agent_id, user_id, permissions, status,
			expires_at, version) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)`,
			id, req.TenantID, req.Agent.ID, userID, permissions, expiresAt, v); err != nil {
			return mapErr(err)
		}
		if out, err = scanConsent(tx.QueryRow(ctx, `SELECT `+consentCols+consentFrom+` WHERE c.id = $1`, id)); err != nil {
			return err
		}
		if req.Current != nil {
			// a narrower consent replaces a wider one at once: tokens got under the old one stop
			if _, err := revokeTokensOf(ctx, tx, req.TenantID, userID, req.Agent.ID, "", RevokeConsentWithdrawn); err != nil {
				return err
			}
		}
		return audit(ctx, tx, req.TenantID, "agent.consent_granted", consentSubject(out), out)
	})
	return out, err
}

func consentSubject(c Consent) string {
	return "tenants/" + c.TenantID.String() + "/agents/" + c.AgentID.String() + "/consents/" + c.ID.String()
}

// MyConsents lists a person's active consents in every tenant.
func (s *Store) MyConsents(ctx context.Context, userID uuid.UUID) ([]Consent, error) {
	var out []Consent
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var err error
		out, err = collectConsents(tx.Query(ctx, `SELECT `+consentCols+consentFrom+`
			WHERE c.user_id = $1 AND c.status = 'active' AND (c.expires_at IS NULL OR c.expires_at > now())
			ORDER BY c.granted_at DESC`, userID))
		return err
	})
	return out, err
}

// AgentConsents lists the active consents people gave an agent (tenant owners and admins).
func (s *Store) AgentConsents(ctx context.Context, sc Scope, tenantID, agentID uuid.UUID) ([]Consent, error) {
	var out []Consent
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if _, err := getAgent(ctx, tx, tenantID, agentID, false); err != nil {
			return err
		}
		var err error
		out, err = collectConsents(tx.Query(ctx, `SELECT `+consentCols+consentFrom+`
			WHERE c.tenant_id = $1 AND c.agent_id = $2 AND c.status = 'active'
			AND (c.expires_at IS NULL OR c.expires_at > now()) ORDER BY c.granted_at DESC`, tenantID, agentID))
		return err
	})
	return out, err
}

// WithdrawConsent ends a consent and revokes the tokens the agent got for the person (§21). by is who withdraws: the
// person (onlyUser set: it must be theirs) or a tenant admin (onlyUser nil; agentID, when set, must be its agent).
func (s *Store) WithdrawConsent(ctx context.Context, sc Scope, tenantID, agentID, consentID uuid.UUID, onlyUser *uuid.UUID, by uuid.UUID) (Consent, error) {
	var out Consent
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := scanConsent(tx.QueryRow(ctx, `SELECT `+consentCols+consentFrom+`
			WHERE c.id = $1 AND c.tenant_id = $2 FOR UPDATE OF c`, consentID, tenantID))
		if err = mapErr(err); err != nil {
			return err
		}
		if cur.Status != "active" || (onlyUser != nil && cur.UserID != *onlyUser) || (agentID != uuid.Nil && cur.AgentID != agentID) {
			return ErrNotFound
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_consent SET status = 'withdrawn', withdrawn_at = now(), withdrawn_by = $2,
			version = $3 WHERE id = $1`, consentID, by, v); err != nil {
			return err
		}
		if out, err = scanConsent(tx.QueryRow(ctx, `SELECT `+consentCols+consentFrom+` WHERE c.id = $1`, consentID)); err != nil {
			return err
		}
		if _, err := revokeTokensOf(ctx, tx, tenantID, cur.UserID, cur.AgentID, "", RevokeConsentWithdrawn); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "agent.consent_withdrawn", consentSubject(out), out)
	})
	return out, err
}

// ConsentTenant is the tenant a consent belongs to (for the person's own withdrawal, which names only the id).
func (s *Store) ConsentTenant(ctx context.Context, consentID uuid.UUID) (uuid.UUID, error) {
	var tid uuid.UUID
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT tenant_id FROM agent_consent WHERE id = $1`, consentID).Scan(&tid))
	})
	return tid, err
}
