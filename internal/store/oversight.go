package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Human oversight of AI agents (TS15, technical specification §20.6).

// AIRetentionDays is the least audit retention of a tenant with agents (EU AI Act Art. 26(6): six months).
const AIRetentionDays = 183

// OversightEvent is a person's decision about what an agent did or wants to do, as the app saw it.
type OversightEvent struct {
	ID       string         `json:"id"`        // the app's id for it, so a retry records once
	Kind     string         `json:"kind"`      // approval, rejection, override, intervention or stop
	AgentID  uuid.UUID      `json:"agent_id"`  // the agent
	PersonID uuid.UUID      `json:"person_id"` // the person who oversaw it
	Action   string         `json:"action"`    // what the agent did or proposed, in the app's words
	Target   string         `json:"target"`    // what it was about (optional)
	Details  map[string]any `json:"details"`   // anything else the app keeps (optional)
	Time     time.Time      `json:"time"`
}

// oversightArticles maps each kind to the EU AI Act provisions it evidences. Every record is also logging under
// Art. 12 and deployer monitoring under Art. 26(5).
var oversightArticles = map[string][]string{
	"approval":     {"Art. 14(4)(d)"},
	"rejection":    {"Art. 14(4)(d)"},
	"override":     {"Art. 14(4)(d)"},
	"intervention": {"Art. 14(4)(e)"},
	"stop":         {"Art. 14(4)(e)"},
}

// RecordOversight records one oversight event as an audit event (action agent.oversight.<kind>, actor the person,
// on behalf of nobody: a person overseeing). It answers whether it was new.
func (s *Store) RecordOversight(ctx context.Context, app App, tenantID uuid.UUID, e OversightEvent) (bool, error) {
	arts, ok := oversightArticles[e.Kind]
	switch {
	case e.ID == "" || len(e.ID) > 200:
		return false, invalid("id is required (at most 200 characters)")
	case !ok:
		return false, invalid("kind must be approval, rejection, override, intervention or stop")
	case e.AgentID == uuid.Nil || e.PersonID == uuid.Nil:
		return false, invalid("agent_id and person_id are required")
	case strings.TrimSpace(e.Action) == "" || len(e.Action) > 1000:
		return false, invalid("action is required (at most 1000 characters)")
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Time.After(time.Now().Add(5*time.Minute)) || e.Time.Before(time.Now().Add(-30*24*time.Hour)) {
		return false, invalid("time must be within the last 30 days")
	}
	created := false
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := tenantUsesApp(ctx, tx, tenantID, app.ID); err != nil {
			return err
		}
		var agentName string
		if err := tx.QueryRow(ctx, `SELECT name FROM agent WHERE id = $1 AND tenant_id = $2 AND status <> 'deleted'`,
			e.AgentID, tenantID).Scan(&agentName); err != nil {
			if err == pgx.ErrNoRows {
				return invalid("agent_id is not an agent of this organisation")
			}
			return err
		}
		m, err := getMember(ctx, tx, tenantID, e.PersonID, false)
		if err != nil || m.Status != "active" || m.Kind != "human" {
			return invalid("person_id must be a person who is an active member of this organisation")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO agent_oversight (tenant_id, app_id, event_id, kind, agent_id, person_id, action, occurred_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`, tenantID, app.ID, e.ID, e.Kind, e.AgentID,
			e.PersonID, e.Action, e.Time)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		created = true
		var email *string
		_ = tx.QueryRow(ctx, `SELECT email FROM app_user WHERE id = $1`, e.PersonID).Scan(&email)
		actor := Actor{Kind: "user", ID: e.PersonID}
		if email != nil {
			actor.Email = *email
		}
		base := ActorFrom(ctx)
		actor.RequestID, actor.IP, actor.UserAgent = base.RequestID, base.IP, base.UserAgent
		subject := "tenants/" + tenantID.String() + "/agents/" + e.AgentID.String() + "/oversight/" + e.ID
		return audit(WithActor(ctx, actor), tx, tenantID, "agent.oversight."+e.Kind, subject, map[string]any{
			"app": app.Slug, "agent_id": e.AgentID, "agent_name": agentName, "action": e.Action, "target": e.Target,
			"details": e.Details, "occurred_at": e.Time, "id": e.ID,
			"eu_ai_act": append([]string{"Art. 12"}, append(arts, "Art. 26(5)")...)})
	})
	return created, err
}

// OversightStats counts a tenant's oversight records in the last 90 days, for readiness.
func oversightCounts(ctx context.Context, tx pgx.Tx) (map[uuid.UUID]int, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_id, count(*) FROM agent_oversight WHERE occurred_at > now() - interval '90 days'
		GROUP BY tenant_id`)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]int{}
	for rows.Next() {
		var id uuid.UUID
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
