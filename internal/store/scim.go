package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SCIM 2.0 provisioning (TS14, technical specification §19): users an identity provider provisioned into a tenant.
// The API turns SCIM resources into these records; Keycloak accounts are created or linked by the API first.

// SCIMUser is a provisioned person in one tenant. UserID is the Matura and Keycloak user id and the SCIM id.
type SCIMUser struct {
	TenantID       uuid.UUID
	UserID         uuid.UUID
	UserName       string
	ExternalID     *string
	Active         bool
	Email          string           // the account's address: the primary (or work, or first) email
	Emails         []map[string]any // as the identity provider sent them
	GivenName      *string
	FamilyName     *string
	DisplayName    *string
	Enterprise     map[string]any // urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
	Extra          map[string]any // other core attributes kept as sent (title, phoneNumbers, locale…)
	CreatedAccount bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Groups         []SCIMRef // the SCIM groups the user is in
}

// SCIMRef points at a SCIM resource, with its display name.
type SCIMRef struct {
	ID      uuid.UUID
	Display string
}

// SCIMCond is one `attr eq "value"` comparison of a SCIM filter; Type narrows emails to one type.
type SCIMCond struct {
	Attr  string // lower case: id, username, externalid, emails, active, displayname, members
	Type  string
	Value string
}

// SCIMQuery is a list request: comparisons joined by `and`, then a page (Offset from 0).
type SCIMQuery struct {
	Conds  []SCIMCond
	Offset int
	Limit  int
}

const scimUserCols = `u.tenant_id, u.user_id, u.user_name, u.external_id, u.active, u.email, u.emails, u.given_name,
	u.family_name, u.display_name, u.enterprise, u.extra, u.created_account, u.version, u.created_at, u.updated_at`

func scanSCIMUser(row pgx.Row) (SCIMUser, error) {
	var u SCIMUser
	var emails, ent, extra []byte
	err := row.Scan(&u.TenantID, &u.UserID, &u.UserName, &u.ExternalID, &u.Active, &u.Email, &emails, &u.GivenName,
		&u.FamilyName, &u.DisplayName, &ent, &extra, &u.CreatedAccount, &u.Version, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return u, mapErr(err)
	}
	if err := json.Unmarshal(emails, &u.Emails); err != nil {
		return u, err
	}
	if err := json.Unmarshal(ent, &u.Enterprise); err != nil {
		return u, err
	}
	return u, json.Unmarshal(extra, &u.Extra)
}

func scimUserTarget(tenantID, userID uuid.UUID) string {
	return "tenants/" + tenantID.String() + "/scim/users/" + userID.String()
}

func jsonOr(v any, empty string) ([]byte, error) {
	if v == nil || reflect.ValueOf(v).IsNil() {
		return []byte(empty), nil
	}
	return json.Marshal(v)
}

// scimGroupsOf fills in the groups of each user.
func scimGroupsOf(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, users []SCIMUser) error {
	if len(users) == 0 {
		return nil
	}
	idx := map[uuid.UUID]int{}
	ids := make([]uuid.UUID, len(users))
	for i, u := range users {
		idx[u.UserID], ids[i] = i, u.UserID
		users[i].Groups = []SCIMRef{}
	}
	rows, err := tx.Query(ctx, `SELECT m.user_id, g.id, g.display_name FROM scim_group_member m
		JOIN scim_group g ON g.tenant_id = m.tenant_id AND g.id = m.group_id
		WHERE m.tenant_id = $1 AND m.user_id = ANY($2) ORDER BY lower(g.display_name)`, tenantID, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var uid uuid.UUID
		var ref SCIMRef
		if err := rows.Scan(&uid, &ref.ID, &ref.Display); err != nil {
			return err
		}
		users[idx[uid]].Groups = append(users[idx[uid]].Groups, ref)
	}
	return rows.Err()
}

func getSCIMUser(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, lock bool) (SCIMUser, error) {
	q := `SELECT ` + scimUserCols + ` FROM scim_user u WHERE u.tenant_id = $1 AND u.user_id = $2`
	if lock {
		q += ` FOR UPDATE`
	}
	u, err := scanSCIMUser(tx.QueryRow(ctx, q, tenantID, userID))
	if err != nil {
		return u, err
	}
	list := []SCIMUser{u}
	err = scimGroupsOf(ctx, tx, tenantID, list)
	return list[0], err
}

// GetSCIMUser reads a provisioned user of the tenant.
func (s *Store) GetSCIMUser(ctx context.Context, tenantID, userID uuid.UUID) (SCIMUser, error) {
	var out SCIMUser
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) (err error) {
		out, err = getSCIMUser(ctx, tx, tenantID, userID, false)
		return err
	})
	return out, err
}

// whereSCIM turns comparisons into SQL; args already holds the tenant id as $1.
func whereSCIM(conds []SCIMCond, cols map[string]string, args *[]any) (string, error) {
	parts := []string{}
	for _, c := range conds {
		*args = append(*args, c.Value)
		n := len(*args)
		switch c.Attr {
		case "emails":
			*args = append(*args, c.Type)
			parts = append(parts, fmt.Sprintf(`EXISTS (SELECT 1 FROM jsonb_array_elements(u.emails) e
				WHERE lower(e->>'value') = lower($%d) AND ($%d = '' OR lower(e->>'type') = lower($%d)))`, n, n+1, n+1))
		case "members":
			parts = append(parts, fmt.Sprintf(`EXISTS (SELECT 1 FROM scim_group_member m WHERE m.tenant_id = g.tenant_id
				AND m.group_id = g.id AND m.user_id::text = lower($%d))`, n))
		case "active":
			parts = append(parts, fmt.Sprintf(`u.active = (lower($%d) = 'true')`, n))
		default:
			col, ok := cols[c.Attr]
			if !ok {
				return "", invalid("filtering on %s is not supported", c.Attr)
			}
			parts = append(parts, fmt.Sprintf(col, n))
		}
	}
	if len(parts) == 0 {
		return "true", nil
	}
	return strings.Join(parts, " AND "), nil
}

var scimUserFilterCols = map[string]string{
	"id":         `u.user_id::text = lower($%d)`,
	"username":   `lower(u.user_name) = lower($%d)`,
	"externalid": `u.external_id = $%d`,
}

// ListSCIMUsers returns one page of the tenant's provisioned users matching q, oldest first, and how many match.
func (s *Store) ListSCIMUsers(ctx context.Context, tenantID uuid.UUID, q SCIMQuery) ([]SCIMUser, int, error) {
	args := []any{tenantID}
	where, err := whereSCIM(q.Conds, scimUserFilterCols, &args)
	if err != nil {
		return nil, 0, err
	}
	var out []SCIMUser
	var total int
	err = s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM scim_user u WHERE u.tenant_id = $1 AND `+where, args...).
			Scan(&total); err != nil {
			return err
		}
		if q.Limit <= 0 {
			out = []SCIMUser{}
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT `+scimUserCols+` FROM scim_user u WHERE u.tenant_id = $1 AND `+where+
			fmt.Sprintf(` ORDER BY u.created_at, u.user_id OFFSET %d LIMIT %d`, q.Offset, q.Limit), args...)
		if err != nil {
			return err
		}
		if out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SCIMUser, error) { return scanSCIMUser(r) }); err != nil {
			return err
		}
		return scimGroupsOf(ctx, tx, tenantID, out)
	})
	return out, total, err
}

// FindSCIMUser finds the tenant's provisioned user with this userName (ignoring case) or, when given, externalId.
func (s *Store) FindSCIMUser(ctx context.Context, tenantID uuid.UUID, userName, externalID string) (SCIMUser, error) {
	var out SCIMUser
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		u, err := scanSCIMUser(tx.QueryRow(ctx, `SELECT `+scimUserCols+` FROM scim_user u WHERE u.tenant_id = $1
			AND (lower(u.user_name) = lower($2) OR ($3 <> '' AND u.external_id = $3))
			ORDER BY (lower(u.user_name) = lower($2)) DESC LIMIT 1`, tenantID, userName, externalID))
		if err != nil {
			return err
		}
		list := []SCIMUser{u}
		err = scimGroupsOf(ctx, tx, tenantID, list)
		out = list[0]
		return err
	})
	return out, err
}

// IsVerifiedDomain says whether the tenant verified the email's domain.
func (s *Store) IsVerifiedDomain(ctx context.Context, tenantID uuid.UUID, email string) (bool, error) {
	domain := EmailDomain(email)
	var ok bool
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_domain WHERE tenant_id = $1 AND domain = $2
			AND verified_at IS NOT NULL)`, tenantID, domain).Scan(&ok)
	})
	return ok && domain != "", err
}

// OtherMemberships counts the user's memberships (any state but removed) in tenants other than this one, personal
// tenants included. It reads across tenants (operator scope).
func (s *Store) OtherMemberships(ctx context.Context, tenantID, userID uuid.UUID) (int, error) {
	var n int
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM membership m JOIN tenant t ON t.id = m.tenant_id
			WHERE m.user_id = $1 AND m.tenant_id <> $2 AND m.status <> 'removed' AND t.status <> 'deleted'`,
			userID, tenantID).Scan(&n)
	})
	return n, err
}

// setMemberStatus activates or deactivates a membership in tx; a removed membership is left alone.
func setMemberStatus(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, status string) error {
	cur, err := getMember(ctx, tx, tenantID, userID, true)
	if err == ErrNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if cur.Status == status || cur.Status == "removed" {
		return nil
	}
	if status != "active" {
		if err := checkNotLastOwner(ctx, tx, tenantID, cur); err != nil {
			return err
		}
	}
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE membership SET status = $3, version = $4, updated_at = now()
		WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID, status, v); err != nil {
		return mapErr(err)
	}
	out, err := getMember(ctx, tx, tenantID, userID, false)
	if err != nil {
		return err
	}
	return emit(ctx, tx, v, tenantID, "membership.updated", memberSubject(tenantID, userID), out)
}

func memberStatus(active bool) string {
	if active {
		return "active"
	}
	return "deactivated"
}

// ProvisionSCIMUser records a provisioned user whose account exists (app_user row included). A person already in
// the tenant (say, who joined through SSO just in time) is adopted; anyone else joins with the SSO connection's
// default tenant role (else member) and each enabled app's default role, within the plan's member limit.
func (s *Store) ProvisionSCIMUser(ctx context.Context, in SCIMUser) (SCIMUser, error) {
	emails, err := jsonOr(in.Emails, "[]")
	if err != nil {
		return SCIMUser{}, err
	}
	ent, err := jsonOr(in.Enterprise, "{}")
	if err != nil {
		return SCIMUser{}, err
	}
	extra, err := jsonOr(in.Extra, "{}")
	if err != nil {
		return SCIMUser{}, err
	}
	tid, uid := in.TenantID, in.UserID
	var out SCIMUser
	err = s.tx(ctx, Scope{TenantID: tid}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tid); err != nil {
			return err
		}
		adopted := false
		cur, err := getMember(ctx, tx, tid, uid, true)
		switch {
		case err == nil && cur.Status != "removed":
			adopted = true
		case err != nil && err != ErrNotFound:
			return err
		default:
			role := "member"
			if err := tx.QueryRow(ctx, `SELECT default_tenant_role FROM tenant_sso WHERE tenant_id = $1`, tid).
				Scan(&role); err != nil && err != pgx.ErrNoRows {
				return err
			}
			if _, err := addMember(ctx, tx, tid, uid, role, true); err != nil {
				return err
			}
			if err := grantDefaults(ctx, tx, tid, uid, nil); err != nil {
				return err
			}
		}
		if err := setMemberStatus(ctx, tx, tid, uid, memberStatus(in.Active)); err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scim_user (tenant_id, user_id, user_name, external_id, active, email,
			emails, given_name, family_name, display_name, enterprise, extra, created_account, version)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`, tid, uid, in.UserName, in.ExternalID,
			in.Active, in.Email, emails, in.GivenName, in.FamilyName, in.DisplayName, ent, extra, in.CreatedAccount,
			v); err != nil {
			return mapErr(err)
		}
		if out, err = getSCIMUser(ctx, tx, tid, uid, false); err != nil {
			return err
		}
		return audit(ctx, tx, tid, "scim.user_provisioned", scimUserTarget(tid, uid), map[string]any{
			"user_name": out.UserName, "external_id": out.ExternalID, "active": out.Active, "adopted": adopted,
			"created_account": out.CreatedAccount})
	})
	return out, err
}

// sameSCIMUser compares what a replacement may change.
func sameSCIMUser(a, b SCIMUser) bool {
	type cmp struct {
		UserName, Email                    string
		ExternalID, Given, Family, Display *string
		Active                             bool
		Emails                             *[]map[string]any
		Enterprise, Extra                  *map[string]any
	}
	x, _ := json.Marshal(cmp{a.UserName, a.Email, a.ExternalID, a.GivenName, a.FamilyName, a.DisplayName, a.Active,
		orNil(a.Emails, len(a.Emails)), orNil(a.Enterprise, len(a.Enterprise)), orNil(a.Extra, len(a.Extra))})
	y, _ := json.Marshal(cmp{b.UserName, b.Email, b.ExternalID, b.GivenName, b.FamilyName, b.DisplayName, b.Active,
		orNil(b.Emails, len(b.Emails)), orNil(b.Enterprise, len(b.Enterprise)), orNil(b.Extra, len(b.Extra))})
	return string(x) == string(y)
}

// orNil makes empty maps and lists compare equal to absent ones.
func orNil[T any](v T, n int) *T {
	if n == 0 {
		return nil
	}
	return &v
}

// ReplaceSCIMUser stores a user's new state (PUT, or PATCH after it is applied). ifVersion, when not 0, must be the
// current version. A replacement that changes nothing keeps the version, so retries are harmless. Deactivating
// deactivates the membership (never the last owner's) and revokes group-made grants; reactivating restores them.
// The person's name and email in Matura follow.
func (s *Store) ReplaceSCIMUser(ctx context.Context, in SCIMUser, ifVersion int64) (SCIMUser, SCIMUser, error) {
	tid, uid := in.TenantID, in.UserID
	var before, out SCIMUser
	err := s.tx(ctx, Scope{TenantID: tid}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tid); err != nil {
			return err
		}
		var err error
		if before, err = getSCIMUser(ctx, tx, tid, uid, true); err != nil {
			return err
		}
		if ifVersion != 0 && before.Version != ifVersion {
			return ErrVersion
		}
		if sameSCIMUser(before, in) {
			out = before
			return nil
		}
		emails, err := jsonOr(in.Emails, "[]")
		if err != nil {
			return err
		}
		ent, err := jsonOr(in.Enterprise, "{}")
		if err != nil {
			return err
		}
		extra, err := jsonOr(in.Extra, "{}")
		if err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scim_user SET user_name = $3, external_id = $4, active = $5, email = $6,
			emails = $7, given_name = $8, family_name = $9, display_name = $10, enterprise = $11, extra = $12,
			version = $13, updated_at = now() WHERE tenant_id = $1 AND user_id = $2`, tid, uid, in.UserName,
			in.ExternalID, in.Active, in.Email, emails, in.GivenName, in.FamilyName, in.DisplayName, ent, extra,
			v); err != nil {
			return mapErr(err)
		}
		if !strings.EqualFold(before.Email, in.Email) || !eqPtr(before.DisplayName, in.DisplayName) {
			if err := updateUserProfile(ctx, tx, uid, in.Email, in.DisplayName); err != nil {
				return err
			}
		}
		if before.Active != in.Active {
			if err := setMemberStatus(ctx, tx, tid, uid, memberStatus(in.Active)); err != nil {
				return err
			}
			if err := reconcileGroupGrants(ctx, tx, tid, []uuid.UUID{uid}); err != nil {
				return err
			}
		}
		if out, err = getSCIMUser(ctx, tx, tid, uid, false); err != nil {
			return err
		}
		return audit(ctx, tx, tid, "scim.user_updated", scimUserTarget(tid, uid), map[string]any{
			"user_name": out.UserName, "external_id": out.ExternalID, "active": out.Active})
	})
	return before, out, err
}

func eqPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// updateUserProfile writes a provisioned person's email and name into Matura's user record.
func updateUserProfile(ctx context.Context, tx pgx.Tx, userID uuid.UUID, email string, name *string) error {
	v, err := nextVersion(ctx, tx)
	if err != nil {
		return err
	}
	u, err := scanUser(tx.QueryRow(ctx, `UPDATE app_user SET email = $2, email_verified = true,
		display_name = coalesce($3, display_name), version = $4, updated_at = now()
		WHERE id = $1 AND status <> 'deleted' RETURNING `+userCols, userID, email, name, v))
	if err == ErrNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	return emit(ctx, tx, v, uuid.Nil, "user.updated", "users/"+userID.String(), u)
}

// DeleteSCIMUser deprovisions a user: they leave the tenant's SCIM groups, their membership is removed and their
// grants in the tenant revoked (contract events). The account itself stays; the API decides about erasure.
func (s *Store) DeleteSCIMUser(ctx context.Context, tenantID, userID uuid.UUID, ifVersion int64) (SCIMUser, error) {
	var cur SCIMUser
	err := s.tx(ctx, Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		var err error
		if cur, err = getSCIMUser(ctx, tx, tenantID, userID, true); err != nil {
			return err
		}
		if ifVersion != 0 && cur.Version != ifVersion {
			return ErrVersion
		}
		m, err := getMember(ctx, tx, tenantID, userID, true)
		if err != nil && err != ErrNotFound {
			return err
		}
		member := err == nil && m.Status != "removed"
		if member {
			if err := checkNotLastOwner(ctx, tx, tenantID, m); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_managed_grant WHERE tenant_id = $1 AND user_id = $2`,
			tenantID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_user WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
			return err
		}
		if member {
			if err := revokeGrantsOf(ctx, tx, tenantID, userID); err != nil {
				return err
			}
			v, err := nextVersion(ctx, tx)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE membership SET status = 'removed', version = $3, updated_at = now()
				WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID, v); err != nil {
				return mapErr(err)
			}
			m.Status, m.Version = "removed", v
			if err := emit(ctx, tx, v, tenantID, "membership.removed", memberSubject(tenantID, userID), m); err != nil {
				return err
			}
		}
		return audit(ctx, tx, tenantID, "scim.user_deprovisioned", scimUserTarget(tenantID, userID), map[string]any{
			"user_name": cur.UserName, "external_id": cur.ExternalID})
	})
	return cur, err
}
