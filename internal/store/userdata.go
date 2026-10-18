package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxUserExportEvents caps the audit events in a user's own export (newest kept); Truncated says when it applied.
var MaxUserExportEvents = 50000

// UserData is everything Matura holds about one person (GDPR Art. 15 and 20; technical specification §14.2).
type UserData struct {
	Format      string           `json:"format"`
	GeneratedAt time.Time        `json:"generated_at"`
	Profile     User             `json:"profile"`
	Memberships []UserMembership `json:"memberships"`
	Grants      []Grant          `json:"grants"`
	Invitations []Invitation     `json:"invitations"`
	Audit       UserAudit        `json:"audit"`
}

// UserMembership is a membership with its tenant's name, in any state.
type UserMembership struct {
	Membership
	TenantSlug string `json:"tenant_slug"`
	TenantName string `json:"tenant_name"`
}

type UserAudit struct {
	Events    []AuditEvent `json:"events"` // where the user is the actor, oldest first
	Truncated bool         `json:"truncated"`
}

// UserExportFormat names the user export's layout.
const UserExportFormat = "matura.user-export/v1"

// ExportUserData gathers the user's profile, memberships, grants (active and revoked), invitations to their
// address, and the audit events they caused, across every tenant, and records user.exported. It reads with
// installation scope because the data spans tenants; every query is filtered to the user.
func (s *Store) ExportUserData(ctx context.Context, userID uuid.UUID) (UserData, error) {
	out := UserData{Format: UserExportFormat, GeneratedAt: time.Now().UTC()}
	err := s.tx(ctx, Scope{UserID: userID, Operator: true}, func(tx pgx.Tx) error {
		var err error
		if out.Profile, err = scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1`, userID)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+memberCols+`, t.slug, t.name FROM membership m
			JOIN app_user u ON u.id = m.user_id JOIN tenant t ON t.id = m.tenant_id
			WHERE m.user_id = $1 ORDER BY t.name`, userID)
		if err != nil {
			return err
		}
		if out.Memberships, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (UserMembership, error) {
			var m UserMembership
			err := r.Scan(&m.TenantID, &m.UserID, &m.TenantRole, &m.Status, &m.JoinedAt, &m.Version, &m.UpdatedAt,
				&m.Email, &m.DisplayName, &m.Kind, &m.TenantSlug, &m.TenantName)
			return m, err
		}); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT `+grantCols+` FROM role_grant g JOIN app a ON a.id = g.app_id
			WHERE g.subject_type = 'user' AND g.subject_id = $1 ORDER BY g.tenant_id, a.slug, g.role, g.id`, userID)
		if err != nil {
			return err
		}
		if out.Grants, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) }); err != nil {
			return err
		}
		email := ""
		if out.Profile.Email != nil {
			email = *out.Profile.Email
		}
		rows, err = tx.Query(ctx, `SELECT `+invitationCols+` FROM invitation
			WHERE ($2 <> '' AND lower(email) = lower($2)) OR accepted_by = $1 ORDER BY created_at`, userID, email)
		if err != nil {
			return err
		}
		if out.Invitations, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Invitation, error) { return scanInvitation(r) }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT * FROM (SELECT `+auditCols+` FROM audit_event WHERE actor_id = $1
			ORDER BY id DESC LIMIT $2) e ORDER BY id`, userID, MaxUserExportEvents+1)
		if err != nil {
			return err
		}
		if out.Audit.Events, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEvent, error) { return scanAudit(r) }); err != nil {
			return err
		}
		if len(out.Audit.Events) > MaxUserExportEvents {
			out.Audit.Events, out.Audit.Truncated = out.Audit.Events[1:], true
		}
		return audit(ctx, tx, uuid.Nil, "user.exported", "users/"+userID.String(), map[string]any{
			"memberships": len(out.Memberships), "grants": len(out.Grants), "invitations": len(out.Invitations),
			"audit_events": len(out.Audit.Events), "truncated": out.Audit.Truncated})
	})
	out.Memberships, out.Grants = nonNilSlice(out.Memberships), nonNilSlice(out.Grants)
	out.Invitations, out.Audit.Events = nonNilSlice(out.Invitations), nonNilSlice(out.Audit.Events)
	return out, err
}
