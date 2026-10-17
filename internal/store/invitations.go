package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// InvitationTTL is how long an invitation link works (UM-2).
const InvitationTTL = 7 * 24 * time.Hour

var (
	// ErrInvitationGone is an invitation that was accepted, revoked or has expired (or a token that never existed).
	ErrInvitationGone = errors.New("this invitation is no longer valid; ask your admin for a new invitation")
	// ErrWrongInvitee is a signed-in user whose email is not the invited one.
	ErrWrongInvitee = errors.New("this invitation was sent to a different email address; sign in with that address")
)

// InvitedRole is an app role an invitation gives on acceptance. WorkspaceID nil means the whole tenant.
type InvitedRole struct {
	App         string     `json:"app"`
	Role        string     `json:"role"`
	WorkspaceID *uuid.UUID `json:"workspace_id,omitempty"`
}

type Invitation struct {
	ID         uuid.UUID     `json:"id"`
	TenantID   uuid.UUID     `json:"tenant_id"`
	Email      string        `json:"email"`
	TenantRole string        `json:"tenant_role"`
	AppRoles   []InvitedRole `json:"app_roles"`
	Delivery   string        `json:"delivery"`
	DeliverTo  *string       `json:"deliver_to"`
	ExpiresAt  time.Time     `json:"expires_at"`
	State      string        `json:"state"` // pending, accepted, revoked, expired
	InvitedBy  *uuid.UUID    `json:"invited_by"`
	AcceptedBy *uuid.UUID    `json:"accepted_by"`
	AcceptedAt *time.Time    `json:"accepted_at"`
	SentCount  int           `json:"sent_count"`
	Version    int64         `json:"version"`
	CreatedAt  time.Time     `json:"created_at"`
}

// Recipient is where the invitation email goes: deliver_to when set, else the invited address.
func (i Invitation) Recipient() string {
	if i.DeliverTo != nil && *i.DeliverTo != "" {
		return *i.DeliverTo
	}
	return i.Email
}

// a pending invitation past its expiry reads as expired without a background job
const invitationCols = `id, tenant_id, email, tenant_role, app_roles, delivery, deliver_to, expires_at,
	CASE WHEN state = 'pending' AND expires_at <= now() THEN 'expired' ELSE state END,
	invited_by, accepted_by, accepted_at, sent_count, version, created_at`

func scanInvitation(row pgx.Row) (Invitation, error) {
	var i Invitation
	var roles []byte
	err := row.Scan(&i.ID, &i.TenantID, &i.Email, &i.TenantRole, &roles, &i.Delivery, &i.DeliverTo, &i.ExpiresAt,
		&i.State, &i.InvitedBy, &i.AcceptedBy, &i.AcceptedAt, &i.SentCount, &i.Version, &i.CreatedAt)
	if err != nil {
		return i, mapErr(err)
	}
	if err := json.Unmarshal(roles, &i.AppRoles); err != nil {
		return i, err
	}
	if i.AppRoles == nil {
		i.AppRoles = []InvitedRole{}
	}
	return i, nil
}

// HashToken is how invitation tokens are stored: only their SHA-256, so a database read does not reveal links.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

type NewInvitation struct {
	Email      string
	TenantRole string
	AppRoles   []InvitedRole
	DeliverTo  string
	InvitedBy  uuid.UUID
	Token      string // the secret in the link; only its hash is kept
}

// Compose writes the email for an invitation; the API supplies it because it knows the public URL and the token.
type Compose func(Invitation) Email

func validEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n<>,;")
}

// CreateInvitation invites someone to the tenant (UM-1). An earlier pending invitation to the same address is
// revoked, so only the newest link works. Someone who is already an active member gets ErrConflict.
func (s *Store) CreateInvitation(ctx context.Context, sc Scope, tenantID uuid.UUID, in NewInvitation, compose Compose) (Invitation, error) {
	in.Email = strings.TrimSpace(in.Email)
	in.DeliverTo = strings.TrimSpace(in.DeliverTo)
	if !validEmail(in.Email) {
		return Invitation{}, invalid("email must be an email address")
	}
	if in.DeliverTo != "" && !validEmail(in.DeliverTo) {
		return Invitation{}, invalid("deliver_to must be an email address")
	}
	if in.TenantRole == "" {
		in.TenantRole = "member"
	}
	if !tenantRoles[in.TenantRole] {
		return Invitation{}, invalid("tenant role must be owner, admin, billing or member")
	}
	if in.AppRoles == nil {
		in.AppRoles = []InvitedRole{}
	}
	var out Invitation
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := checkInvitedRoles(ctx, tx, tenantID, in.AppRoles); err != nil {
			return err
		}
		var member bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM membership m JOIN app_user u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND lower(u.email) = lower($2) AND m.status = 'active')`,
			tenantID, in.Email).Scan(&member); err != nil {
			return err
		}
		if member {
			return fmt.Errorf("%w: %s is already a member", ErrConflict, in.Email)
		}
		if _, err := tx.Exec(ctx, `UPDATE invitation SET state = 'revoked' WHERE tenant_id = $1
			AND lower(email) = lower($2) AND state = 'pending'`, tenantID, in.Email); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		roles, _ := json.Marshal(in.AppRoles)
		var deliverTo, invitedBy any
		if in.DeliverTo != "" {
			deliverTo = in.DeliverTo
		}
		if in.InvitedBy != uuid.Nil {
			invitedBy = in.InvitedBy
		}
		if out, err = scanInvitation(tx.QueryRow(ctx, `INSERT INTO invitation (id, tenant_id, email, tenant_role,
			app_roles, delivery, deliver_to, token_hash, expires_at, state, invited_by, sent_count, version)
			VALUES ($1, $2, $3, $4, $5, 'link', $6, $7, now() + $8 * interval '1 second', 'pending', $9, 1, $10)
			RETURNING `+invitationCols, ids.New(), tenantID, in.Email, in.TenantRole, roles, deliverTo,
			HashToken(in.Token), int64(InvitationTTL.Seconds()), invitedBy, v)); err != nil {
			return err
		}
		return enqueueEmail(ctx, tx, tenantID, compose(out))
	})
	return out, err
}

// checkInvitedRoles refuses roles that could not be granted now: an unknown or disabled app, a role the app does
// not have, or a workspace of another tenant.
func checkInvitedRoles(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, roles []InvitedRole) error {
	for _, r := range roles {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app a
			JOIN tenant_app ta ON ta.app_id = a.id AND ta.tenant_id = $1 AND ta.status = 'enabled'
			JOIN app_role ar ON ar.app_id = a.id AND ar.name = $3
			WHERE a.slug = $2)`, tenantID, r.App, r.Role).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return invalid("%s is not an enabled app with a role %q", r.App, r.Role)
		}
		if r.WorkspaceID != nil {
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace WHERE tenant_id = $1 AND id = $2)`,
				tenantID, *r.WorkspaceID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return invalid("workspace %s is not in this tenant", r.WorkspaceID)
			}
		}
	}
	return nil
}

func (s *Store) ListInvitations(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]Invitation, error) {
	var out []Invitation
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+invitationCols+` FROM invitation WHERE tenant_id = $1
			ORDER BY created_at DESC LIMIT 500`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Invitation, error) { return scanInvitation(r) })
		return err
	})
	return out, err
}

func getInvitation(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (Invitation, error) {
	return scanInvitation(tx.QueryRow(ctx, `SELECT `+invitationCols+` FROM invitation
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id))
}

// ResendInvitation gives a pending or expired invitation a new link and expiry and sends it again; the old link
// stops working.
func (s *Store) ResendInvitation(ctx context.Context, sc Scope, tenantID, id uuid.UUID, token string, compose Compose) (Invitation, error) {
	var out Invitation
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := getInvitation(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		if cur.State != "pending" && cur.State != "expired" {
			return invalid("this invitation was %s; send a new one instead", cur.State)
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if out, err = scanInvitation(tx.QueryRow(ctx, `UPDATE invitation SET token_hash = $3, state = 'pending',
			expires_at = now() + $4 * interval '1 second', sent_count = sent_count + 1, version = $5
			WHERE tenant_id = $1 AND id = $2 RETURNING `+invitationCols,
			tenantID, id, HashToken(token), int64(InvitationTTL.Seconds()), v)); err != nil {
			return err
		}
		return enqueueEmail(ctx, tx, tenantID, compose(out))
	})
	return out, err
}

// RevokeInvitation stops a pending invitation's link from working.
func (s *Store) RevokeInvitation(ctx context.Context, sc Scope, tenantID, id uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := getInvitation(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		if cur.State == "accepted" {
			return invalid("this invitation was already accepted; remove the member instead")
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE invitation SET state = 'revoked', version = $3 WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, v)
		return err
	})
}

// AcceptInvitation adds the signed-in user to the invitation's tenant with its tenant role and app roles, plus
// each other enabled app's default role (RL-4). The user's email must be the invited one. A user who is already
// a member keeps their tenant role and gains the invitation's app roles. An app role that can no longer be granted
// (the app was disabled or the role deleted since) is skipped.
func (s *Store) AcceptInvitation(ctx context.Context, userID uuid.UUID, email, token string) (Invitation, Membership, error) {
	var tenantID uuid.UUID
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id FROM invitation WHERE token_hash = $1`, HashToken(token)).Scan(&tenantID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, Membership{}, ErrInvitationGone
	}
	if err != nil {
		return Invitation{}, Membership{}, err
	}
	var inv Invitation
	var m Membership
	err = s.tx(ctx, Scope{TenantID: tenantID, UserID: userID}, func(tx pgx.Tx) error {
		var err error
		if inv, err = scanInvitation(tx.QueryRow(ctx, `SELECT `+invitationCols+` FROM invitation
			WHERE tenant_id = $1 AND token_hash = $2 FOR UPDATE`, tenantID, HashToken(token))); err != nil {
			return ErrInvitationGone
		}
		var tenantStatus string
		if err := tx.QueryRow(ctx, `SELECT status FROM tenant WHERE id = $1`, tenantID).Scan(&tenantStatus); err != nil {
			return mapErr(err)
		}
		if inv.State != "pending" || tenantStatus != "active" {
			return ErrInvitationGone
		}
		if !strings.EqualFold(strings.TrimSpace(email), inv.Email) {
			return ErrWrongInvitee
		}
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		m, err = addMember(ctx, tx, tenantID, userID, inv.TenantRole, true)
		if errors.Is(err, ErrConflict) { // already a member: keep the role they have
			err = nil
		}
		if err != nil {
			return err
		}
		named := map[string]bool{}
		for _, r := range inv.AppRoles {
			named[r.App] = true
			// a savepoint, so a grant that fails (say it already exists) does not abort the acceptance
			err := pgx.BeginFunc(ctx, tx, func(sp pgx.Tx) error {
				_, err := createGrant(ctx, sp, tenantID, NewGrant{App: r.App, UserID: userID, Role: r.Role,
					WorkspaceID: r.WorkspaceID})
				return err
			})
			var bad *InvalidError
			if err != nil && !errors.Is(err, ErrConflict) && !errors.As(err, &bad) {
				return err
			}
		}
		if err := grantDefaults(ctx, tx, tenantID, userID, named); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if inv, err = scanInvitation(tx.QueryRow(ctx, `UPDATE invitation SET state = 'accepted', accepted_by = $3,
			accepted_at = now(), version = $4 WHERE tenant_id = $1 AND id = $2 RETURNING `+invitationCols,
			tenantID, inv.ID, userID, v)); err != nil {
			return err
		}
		m, err = getMember(ctx, tx, tenantID, userID, false)
		return err
	})
	return inv, m, err
}

// InvitationPreview is what the accept page shows to whoever holds the link, before they sign in.
type InvitationPreview struct {
	TenantName string    `json:"tenant_name"`
	Email      string    `json:"email"`
	State      string    `json:"state"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// PreviewInvitation looks an invitation up by its token; ErrInvitationGone when the token is unknown.
func (s *Store) PreviewInvitation(ctx context.Context, token string) (InvitationPreview, error) {
	var out InvitationPreview
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT t.name, i.email,
			CASE WHEN i.state = 'pending' AND (i.expires_at <= now() OR t.status <> 'active') THEN 'expired'
			     ELSE i.state END, i.expires_at
			FROM invitation i JOIN tenant t ON t.id = i.tenant_id WHERE i.token_hash = $1`,
			HashToken(token)).Scan(&out.TenantName, &out.Email, &out.State, &out.ExpiresAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrInvitationGone
	}
	return out, err
}
