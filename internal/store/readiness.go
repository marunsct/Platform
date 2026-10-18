package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TenantPosture is a tenant with the settings readiness checks look at (TS24).
type TenantPosture struct {
	Tenant           Tenant
	Policy           SecurityPolicy
	SinksActive      int // audit destinations delivering
	SinksFailing     int
	LastAccessReview *time.Time // the newest completed access review (§18.4)
}

// TenantPostures reads every tenant that is not deleted, with its security policy and audit destinations, in one
// query in operator scope.
func (s *Store) TenantPostures(ctx context.Context) ([]TenantPosture, error) {
	var out []TenantPosture
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT t.id, t.slug, t.name, t.kind, t.status, t.plan, t.data_mode_default,
				t.version, t.created_at, t.updated_at,
				coalesce(p.require_mfa, false), p.session_max_age, p.idle_timeout,
				coalesce(p.allowed_email_domains, '{}'), coalesce(p.ip_allowlist, '{}'), coalesce(p.version, 0), p.updated_at,
				(SELECT count(*) FROM audit_sink a WHERE a.tenant_id = t.id AND a.status = 'active'),
				(SELECT count(*) FROM audit_sink a WHERE a.tenant_id = t.id AND a.status = 'failing'),
				(SELECT max(completed_at) FROM access_review r WHERE r.tenant_id = t.id AND r.status = 'completed')
			FROM tenant t LEFT JOIN security_policy p ON p.tenant_id = t.id
			WHERE t.status <> 'deleted' ORDER BY t.slug`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TenantPosture, error) {
			var tp TenantPosture
			t, p := &tp.Tenant, &tp.Policy
			err := r.Scan(&t.ID, &t.Slug, &t.Name, &t.Kind, &t.Status, &t.Plan, &t.DataModeDefault, &t.Version,
				&t.CreatedAt, &t.UpdatedAt, &p.RequireMFA, &p.SessionMaxAge, &p.IdleTimeout, &p.AllowedEmailDomains,
				&p.IPAllowlist, &p.Version, &p.UpdatedAt, &tp.SinksActive, &tp.SinksFailing, &tp.LastAccessReview)
			p.TenantID = t.ID
			return tp, err
		})
		return err
	})
	return out, err
}

// WebhookHealth counts app webhook endpoints by state, in operator scope.
type WebhookHealth struct {
	Active   int // not disabled
	Failing  int
	Disabled int
	Dropped  int64 // events given up on, summed over endpoints that are not disabled
}

func (s *Store) WebhookHealth(ctx context.Context) (WebhookHealth, error) {
	var h WebhookHealth
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status <> 'disabled'),
				count(*) FILTER (WHERE status = 'failing'), count(*) FILTER (WHERE status = 'disabled'),
				coalesce(sum(dropped) FILTER (WHERE status <> 'disabled'), 0)
			FROM webhook_endpoint`).Scan(&h.Active, &h.Failing, &h.Disabled, &h.Dropped)
	})
	return h, err
}

// EvidenceRecord is evidence an operator or a script reported (restore tests, access reviews, scans). It is kept
// as an event in the installation audit chain, action "evidence.<kind>", so it is tamper-evident like the rest.
type EvidenceRecord struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Passed     bool            `json:"passed"`
	Details    json.RawMessage `json:"details"`
	RecordedAt time.Time       `json:"recorded_at"`
	RecordedBy string          `json:"recorded_by"`
	Seq        int64           `json:"seq"`
	Hash       string          `json:"hash"`
}

func evidenceFrom(e AuditEvent) EvidenceRecord {
	var d struct {
		Kind    string          `json:"kind"`
		Passed  bool            `json:"passed"`
		Details json.RawMessage `json:"details"`
	}
	_ = json.Unmarshal(e.Data, &d)
	if len(d.Details) == 0 {
		d.Details = json.RawMessage("{}")
	}
	by := e.Actor.Email
	if by == "" && e.Actor.ID != nil {
		by = e.Actor.ID.String()
	}
	return EvidenceRecord{ID: e.ID, Kind: d.Kind, Passed: d.Passed, Details: d.Details, RecordedAt: e.Time,
		RecordedBy: by, Seq: e.Seq, Hash: e.Hash}
}

// RecordEvidence appends evidence to the installation audit chain and returns it as stored.
func (s *Store) RecordEvidence(ctx context.Context, sc Scope, kind string, passed bool, details json.RawMessage) (EvidenceRecord, error) {
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	var out EvidenceRecord
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		if err := audit(ctx, tx, uuid.Nil, "evidence."+kind, "evidence/"+kind,
			map[string]any{"kind": kind, "passed": passed, "details": details}); err != nil {
			return err
		}
		// the chain's head row is locked until commit, so the newest installation event is the one just written
		e, err := scanAudit(tx.QueryRow(ctx, `SELECT `+auditCols+` FROM audit_event
			WHERE tenant_id IS NULL ORDER BY seq DESC LIMIT 1`))
		out = evidenceFrom(e)
		return err
	})
	return out, err
}

// ListEvidence returns evidence of one kind (all kinds when empty) newest first, recorded at or after since when set.
func (s *Store) ListEvidence(ctx context.Context, sc Scope, kind string, since *time.Time, limit int) ([]EvidenceRecord, error) {
	events, err := s.ListAudit(ctx, sc, AuditQuery{Installation: true, Action: "evidence." + kind, From: since, Limit: limit})
	out := make([]EvidenceRecord, 0, len(events))
	for _, e := range events {
		out = append(out, evidenceFrom(e))
	}
	return out, err
}
