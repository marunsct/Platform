package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Agents (TS15, technical specification §18): tenant service accounts (kind service) and AI agents (kind agent).
// Each is a Keycloak confidential client whose service-account user is an app_user row of that kind and an active
// member of its tenant, so grants, tokens and contract events work as for people. The API creates the Keycloak
// client first and records it here; the client secret is never stored by Matura.

// Agent is a tenant's service account or AI agent.
type Agent struct {
	ID              uuid.UUID  `json:"id"` // also the user id: the sub of its tokens
	TenantID        uuid.UUID  `json:"tenant_id"`
	Kind            string     `json:"kind"`
	Name            string     `json:"name"`
	Description     *string    `json:"description"`
	OwnerID         *uuid.UUID `json:"owner_id"`
	ClientID        string     `json:"client_id"`
	ClientUUID      string     `json:"-"`
	Status          string     `json:"status"`
	ExpiresAt       *time.Time `json:"expires_at"`
	SecretRotatedAt time.Time  `json:"secret_rotated_at"`
	Version         int64      `json:"version"`
	CreatedBy       *uuid.UUID `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Grants          []Grant    `json:"grants"`
}

const agentCols = `id, tenant_id, kind, name, description, owner_id, client_id, client_uuid, status, expires_at,
	secret_rotated_at, version, created_by, created_at, updated_at`

func scanAgent(row pgx.Row) (Agent, error) {
	var a Agent
	err := row.Scan(&a.ID, &a.TenantID, &a.Kind, &a.Name, &a.Description, &a.OwnerID, &a.ClientID, &a.ClientUUID,
		&a.Status, &a.ExpiresAt, &a.SecretRotatedAt, &a.Version, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	a.Grants = []Grant{}
	return a, mapErr(err)
}

func agentSubject(a Agent) string {
	return "tenants/" + a.TenantID.String() + "/agents/" + a.ID.String()
}

// auditAgent is the agent as the audit log records it.
func auditAgent(a Agent) map[string]any {
	return map[string]any{"id": a.ID, "kind": a.Kind, "name": a.Name, "client_id": a.ClientID, "status": a.Status,
		"owner_id": a.OwnerID, "expires_at": a.ExpiresAt, "version": a.Version}
}

// NewAgent is what an owner or admin asks for. Grants name apps and roles; UserID in them is ignored.
type NewAgent struct {
	Kind        string
	Name        string
	Description string
	OwnerID     uuid.UUID // empty: the creator
	ExpiresAt   *time.Time
	Grants      []NewGrant
}

// Check validates what can be checked before anything is created in Keycloak.
func (in *NewAgent) Check(now time.Time) error {
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Kind != "service" && in.Kind != "agent":
		return invalid("kind must be service or agent")
	case in.Name == "" || len(in.Name) > 100:
		return invalid("name is required (at most 100 characters)")
	case len(in.Description) > 1000:
		return invalid("description is at most 1000 characters")
	case in.ExpiresAt != nil && !in.ExpiresAt.After(now):
		return invalid("expires_at must be in the future")
	}
	return nil
}

// CheckNewAgent checks the owner and the plan's agent limit before the Keycloak client is created.
func (s *Store) CheckNewAgent(ctx context.Context, sc Scope, tenantID uuid.UUID, in NewAgent) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := checkAgentOwner(ctx, tx, tenantID, in.OwnerID); err != nil {
			return err
		}
		return checkAgentLimit(ctx, tx, tenantID)
	})
}

func checkAgentOwner(ctx context.Context, tx pgx.Tx, tenantID, ownerID uuid.UUID) error {
	var kind, status string
	err := tx.QueryRow(ctx, `SELECT u.kind, m.status FROM membership m JOIN app_user u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.user_id = $2`, tenantID, ownerID).Scan(&kind, &status)
	if err == pgx.ErrNoRows || (err == nil && (status != "active" || kind != "human")) {
		return invalid("the owner must be a person who is an active member of this tenant")
	}
	return err
}

// CreateAgent records an agent whose Keycloak client exists: its user (kind service or agent), its membership in
// the tenant (role member), the agent row and its grants, with contract events for the user, membership and grants.
func (s *Store) CreateAgent(ctx context.Context, sc Scope, tenantID uuid.UUID, in NewAgent, clientID, clientUUID string,
	userID uuid.UUID) (Agent, error) {
	var out Agent
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := checkAgentOwner(ctx, tx, tenantID, in.OwnerID); err != nil {
			return err
		}
		if err := checkAgentLimit(ctx, tx, tenantID); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		u, err := scanUser(tx.QueryRow(ctx, `INSERT INTO app_user (id, display_name, kind, status, version)
			VALUES ($1, $2, $3, 'active', $4) RETURNING `+userCols, userID, in.Name, in.Kind, v))
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, v, uuid.Nil, "user.created", "users/"+userID.String(), u); err != nil {
			return err
		}
		if _, err := addMember(ctx, tx, tenantID, userID, "member", false); err != nil {
			return err
		}
		if v, err = nextVersion(ctx, tx); err != nil {
			return err
		}
		creator := ActorFrom(ctx).ID
		out, err = scanAgent(tx.QueryRow(ctx, `INSERT INTO agent (id, tenant_id, kind, name, description, owner_id,
			client_id, client_uuid, status, expires_at, version, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, $11) RETURNING `+agentCols,
			userID, tenantID, in.Kind, in.Name, nullable(in.Description), in.OwnerID, clientID, clientUUID,
			in.ExpiresAt, v, nilIfZero(creator)))
		if err != nil {
			return err
		}
		if err := audit(ctx, tx, tenantID, "agent.created", agentSubject(out), auditAgent(out)); err != nil {
			return err
		}
		for _, g := range in.Grants {
			g.UserID = userID
			if _, err := createGrant(ctx, tx, tenantID, g); err != nil {
				return err
			}
		}
		out.Grants, err = agentGrants(ctx, tx, tenantID, userID)
		return err
	})
	return out, err
}

func nilIfZero(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func agentGrants(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID) ([]Grant, error) {
	rows, err := tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
		WHERE g.tenant_id = $1 AND g.subject_type = 'user' AND g.subject_id = $2 AND g.status = 'active'
		ORDER BY a.slug, g.role, g.id`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
}

func getAgent(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID, lock bool) (Agent, error) {
	q := `SELECT ` + agentCols + ` FROM agent WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'`
	if lock {
		q += ` FOR UPDATE`
	}
	a, err := scanAgent(tx.QueryRow(ctx, q, tenantID, id))
	if err != nil {
		return a, err
	}
	a.Grants, err = agentGrants(ctx, tx, tenantID, id)
	return a, err
}

func (s *Store) GetAgent(ctx context.Context, sc Scope, tenantID, id uuid.UUID) (Agent, error) {
	var out Agent
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		out, err = getAgent(ctx, tx, tenantID, id, false)
		return err
	})
	return out, err
}

// ListAgents returns the tenant's agents that are not deleted, by name, with their grants.
func (s *Store) ListAgents(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]Agent, error) {
	out := []Agent{}
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+agentCols+` FROM agent WHERE tenant_id = $1 AND status <> 'deleted'
			ORDER BY lower(name), id`, tenantID)
		if err != nil {
			return err
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Agent, error) { return scanAgent(r) })
		if err != nil {
			return err
		}
		grants, err := tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
			JOIN agent ag ON ag.id = g.subject_id AND ag.tenant_id = g.tenant_id
			WHERE g.tenant_id = $1 AND g.subject_type = 'user' AND g.status = 'active' ORDER BY a.slug, g.role, g.id`,
			tenantID)
		if err != nil {
			return err
		}
		all, err := pgx.CollectRows(grants, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
		if err != nil {
			return err
		}
		by := map[uuid.UUID][]Grant{}
		for _, g := range all {
			by[g.SubjectID] = append(by[g.SubjectID], g)
		}
		for _, a := range list {
			if g := by[a.ID]; g != nil {
				a.Grants = g
			}
			out = append(out, a)
		}
		return nil
	})
	return out, err
}

// AgentPatch changes an agent. ClearExpiry removes expires_at; Status is active or deactivated.
type AgentPatch struct {
	Name        *string
	Description *string
	OwnerID     *uuid.UUID
	ExpiresAt   *time.Time
	ClearExpiry bool
	Status      *string
}

// UpdateAgent applies p after the API changed the Keycloak client. A new name renames the user (user.updated);
// deactivating sets the user deactivated (user.deactivated), so no token is issued for it or on its behalf.
func (s *Store) UpdateAgent(ctx context.Context, sc Scope, tenantID, id uuid.UUID, p AgentPatch, ifMatch int64) (Agent, error) {
	var out Agent
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := getAgent(ctx, tx, tenantID, id, true)
		if err != nil {
			return err
		}
		if ifMatch != 0 && cur.Version != ifMatch {
			return ErrVersion
		}
		next := cur
		if p.Name != nil {
			next.Name = strings.TrimSpace(*p.Name)
			if next.Name == "" || len(next.Name) > 100 {
				return invalid("name is required (at most 100 characters)")
			}
		}
		if p.Description != nil {
			if len(*p.Description) > 1000 {
				return invalid("description is at most 1000 characters")
			}
			next.Description = nullable(*p.Description)
		}
		if p.OwnerID != nil {
			if err := checkAgentOwner(ctx, tx, tenantID, *p.OwnerID); err != nil {
				return err
			}
			next.OwnerID = p.OwnerID
		}
		if p.ClearExpiry {
			next.ExpiresAt = nil
		} else if p.ExpiresAt != nil {
			if !p.ExpiresAt.After(time.Now()) {
				return invalid("expires_at must be in the future")
			}
			next.ExpiresAt = p.ExpiresAt
		}
		if p.Status != nil {
			if *p.Status != "active" && *p.Status != "deactivated" {
				return invalid("status can be active or deactivated; use DELETE to delete an agent")
			}
			next.Status = *p.Status
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if out, err = scanAgent(tx.QueryRow(ctx, `UPDATE agent SET name = $3, description = $4, owner_id = $5,
			expires_at = $6, status = $7, version = $8, updated_at = now() WHERE tenant_id = $1 AND id = $2
			RETURNING `+agentCols, tenantID, id, next.Name, next.Description, next.OwnerID, next.ExpiresAt,
			next.Status, v)); err != nil {
			return err
		}
		action := "agent.updated"
		switch {
		case cur.Status != next.Status && next.Status == "deactivated":
			action = "agent.deactivated"
		case cur.Status != next.Status:
			action = "agent.reactivated"
		}
		if err := audit(ctx, tx, tenantID, action, agentSubject(out), auditAgent(out)); err != nil {
			return err
		}
		if next.Name != cur.Name || next.Status != cur.Status {
			if err := setAgentUser(ctx, tx, id, next.Name, next.Status); err != nil {
				return err
			}
		}
		out.Grants = cur.Grants
		return nil
	})
	return out, err
}

// setAgentUser mirrors an agent's name and status onto its user row, with the contract event apps apply.
func setAgentUser(ctx context.Context, tx pgx.Tx, id uuid.UUID, name, status string) error {
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return err
	}
	u, err := scanUser(tx.QueryRow(ctx, `UPDATE app_user SET display_name = $2, status = $3, version = $4,
		updated_at = now() WHERE id = $1 RETURNING `+userCols, id, name, status, v))
	if err != nil {
		return err
	}
	typ := "user.updated"
	switch status {
	case "deactivated":
		typ = "user.deactivated"
	case "deleted":
		typ = "user.deleted"
	}
	return emit(ctx, tx, v, uuid.Nil, typ, "users/"+id.String(), u)
}

// DeleteAgent ends an agent whose Keycloak client is gone: its grants are revoked, its membership removed and its
// user marked deleted (contract events), and the row is kept as deleted for the audit trail.
func (s *Store) DeleteAgent(ctx context.Context, sc Scope, tenantID, id uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := getAgent(ctx, tx, tenantID, id, true)
		if err != nil {
			return err
		}
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := revokeGrantsOf(ctx, tx, tenantID, id); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE membership SET status = 'removed', version = $3, updated_at = now()
			WHERE tenant_id = $1 AND user_id = $2`, tenantID, id, v); err != nil {
			return mapErr(err)
		}
		m, err := getMember(ctx, tx, tenantID, id, false)
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, v, tenantID, "membership.removed", memberSubject(tenantID, id), m); err != nil {
			return err
		}
		if v, err = nextVersion(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent SET status = 'deleted', version = $3, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, v); err != nil {
			return err
		}
		cur.Status, cur.Version = "deleted", v
		if err := audit(ctx, tx, tenantID, "agent.deleted", agentSubject(cur), auditAgent(cur)); err != nil {
			return err
		}
		return setAgentUser(ctx, tx, id, cur.Name, "deleted")
	})
}

// AgentSecretRotated records that the API rotated the agent's Keycloak client secret.
func (s *Store) AgentSecretRotated(ctx context.Context, sc Scope, tenantID, id uuid.UUID) (Agent, error) {
	var out Agent
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if _, err := getAgent(ctx, tx, tenantID, id, true); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent SET secret_rotated_at = now(), version = $3, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, v); err != nil {
			return err
		}
		if out, err = getAgent(ctx, tx, tenantID, id, false); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "agent.secret_rotated", agentSubject(out), auditAgent(out))
	})
	return out, err
}

// checkAgentLimit refuses a new agent when the tenant has max_agents agents that are not deleted.
func checkAgentLimit(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if err := lockTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	l, err := effectiveLimits(ctx, tx, tenantID)
	if err != nil || l.MaxAgents == nil {
		return err
	}
	var used int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent WHERE tenant_id = $1 AND status <> 'deleted'`,
		tenantID).Scan(&used); err != nil {
		return err
	}
	if atLimit(l.MaxAgents, used) {
		return &LimitError{Limit: "max_agents", Max: l.MaxAgents, Used: used,
			Msg: fmt.Sprintf("the plan allows %d agents and service accounts and the organisation has %d", *l.MaxAgents, used)}
	}
	return nil
}

// agentByClient finds the agent that owns a Keycloak client id, in any tenant (for the token mapper).
func agentByClient(ctx context.Context, tx pgx.Tx, clientID string) (Agent, error) {
	return scanAgent(tx.QueryRow(ctx, `SELECT `+agentCols+` FROM agent WHERE client_id = $1`, clientID))
}
