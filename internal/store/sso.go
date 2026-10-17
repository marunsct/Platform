package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Domain is an email domain a tenant claims (TS13). It counts once its DNS challenge is verified.
type Domain struct {
	TenantID      uuid.UUID  `json:"tenant_id"`
	Domain        string     `json:"domain"`
	Challenge     string     `json:"-"`
	VerifiedAt    *time.Time `json:"verified_at"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	LastError     *string    `json:"last_error"`
	Version       int64      `json:"version"`
	CreatedAt     time.Time  `json:"created_at"`
}

const domainCols = `tenant_id, domain, challenge, verified_at, last_checked_at, last_error, version, created_at`

func scanDomain(row pgx.Row) (Domain, error) {
	var d Domain
	err := row.Scan(&d.TenantID, &d.Domain, &d.Challenge, &d.VerifiedAt, &d.LastCheckedAt, &d.LastError, &d.Version,
		&d.CreatedAt)
	return d, mapErr(err)
}

func domainTarget(tenantID uuid.UUID, domain string) string {
	return "tenants/" + tenantID.String() + "/domains/" + domain
}

// NormalizeDomain lower-cases a domain name and checks its form.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) > 253 || !domainRE.MatchString(d) {
		return "", invalid("%q is not a domain name", d)
	}
	return d, nil
}

// EmailDomain is the lower-cased part after the last @, or "" when there is none.
func EmailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// AddDomain claims a domain for the tenant with the given DNS challenge value.
func (s *Store) AddDomain(ctx context.Context, sc Scope, tenantID uuid.UUID, domain, challenge string) (Domain, error) {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return Domain{}, err
	}
	var out Domain
	err = s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if out, err = scanDomain(tx.QueryRow(ctx, `INSERT INTO tenant_domain (tenant_id, domain, challenge, version)
			VALUES ($1, $2, $3, $4) RETURNING `+domainCols, tenantID, domain, challenge, v)); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "domain.added", domainTarget(tenantID, domain), map[string]any{"domain": domain})
	})
	return out, err
}

func (s *Store) ListDomains(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]Domain, error) {
	var out []Domain
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+domainCols+` FROM tenant_domain WHERE tenant_id = $1 ORDER BY domain`,
			tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Domain, error) { return scanDomain(r) })
		return err
	})
	return out, err
}

func (s *Store) GetDomain(ctx context.Context, sc Scope, tenantID uuid.UUID, domain string) (Domain, error) {
	var out Domain
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) (err error) {
		out, err = scanDomain(tx.QueryRow(ctx, `SELECT `+domainCols+` FROM tenant_domain
			WHERE tenant_id = $1 AND domain = $2`, tenantID, strings.ToLower(domain)))
		return err
	})
	return out, err
}

// RecordDomainCheck stores the outcome of a DNS check: verified when checkErr is empty. A domain another tenant
// verified first answers ErrConflict.
func (s *Store) RecordDomainCheck(ctx context.Context, sc Scope, tenantID uuid.UUID, domain, checkErr string) (Domain, error) {
	var out Domain
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		cur, err := scanDomain(tx.QueryRow(ctx, `SELECT `+domainCols+` FROM tenant_domain
			WHERE tenant_id = $1 AND domain = $2 FOR UPDATE`, tenantID, domain))
		if err != nil {
			return err
		}
		if checkErr != "" {
			out, err = scanDomain(tx.QueryRow(ctx, `UPDATE tenant_domain SET last_checked_at = now(), last_error = $3
				WHERE tenant_id = $1 AND domain = $2 RETURNING `+domainCols, tenantID, domain, checkErr))
			return err
		}
		if cur.VerifiedAt != nil {
			out = cur
			return nil
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		out, err = scanDomain(tx.QueryRow(ctx, `UPDATE tenant_domain SET verified_at = now(), last_checked_at = now(),
			last_error = NULL, version = $3 WHERE tenant_id = $1 AND domain = $2 RETURNING `+domainCols,
			tenantID, domain, v))
		if errors.Is(err, ErrConflict) {
			return errDomainConflict()
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "domain.verified", domainTarget(tenantID, domain), map[string]any{"domain": domain})
	})
	return out, err
}

func errDomainConflict() error {
	return fmt.Errorf("%w: another organisation has already verified this domain", ErrConflict)
}

func (s *Store) DeleteDomain(ctx context.Context, sc Scope, tenantID uuid.UUID, domain string) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM tenant_domain WHERE tenant_id = $1 AND domain = $2`, tenantID,
			strings.ToLower(domain))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(ctx, tx, tenantID, "domain.removed", domainTarget(tenantID, domain), map[string]any{"domain": domain})
	})
}

// SSOConnection is a tenant's identity provider (TS13). Config holds the non-secret settings; the OIDC client
// secret is kept sealed in SealedSecret and never returned.
type SSOConnection struct {
	TenantID          uuid.UUID         `json:"tenant_id"`
	Alias             string            `json:"alias"`
	Protocol          string            `json:"protocol"`
	DisplayName       string            `json:"display_name"`
	Config            map[string]string `json:"config"`
	SealedSecret      []byte            `json:"-"`
	DefaultTenantRole string            `json:"default_tenant_role"`
	Version           int64             `json:"version"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

const ssoCols = `tenant_id, alias, protocol, display_name, config, client_secret, default_tenant_role, version,
	created_at, updated_at`

func scanSSO(row pgx.Row) (SSOConnection, error) {
	var c SSOConnection
	var cfg []byte
	err := row.Scan(&c.TenantID, &c.Alias, &c.Protocol, &c.DisplayName, &cfg, &c.SealedSecret, &c.DefaultTenantRole,
		&c.Version, &c.CreatedAt, &c.UpdatedAt)
	if err == nil {
		err = json.Unmarshal(cfg, &c.Config)
	}
	return c, mapErr(err)
}

// SSOAAD is the associated data the connection's client secret is sealed with.
func SSOAAD(tenantID uuid.UUID) string { return "tenant_sso:" + tenantID.String() }

func ssoTarget(tenantID uuid.UUID) string { return "tenants/" + tenantID.String() + "/sso" }

// CreateSSO records the tenant's SSO connection; ErrConflict when it already has one.
func (s *Store) CreateSSO(ctx context.Context, sc Scope, c SSOConnection) (SSOConnection, error) {
	if c.Protocol != "oidc" && c.Protocol != "saml" {
		return SSOConnection{}, invalid("protocol must be oidc or saml")
	}
	if c.DefaultTenantRole == "" {
		c.DefaultTenantRole = "member"
	}
	if c.DefaultTenantRole == "owner" || !tenantRoles[c.DefaultTenantRole] {
		return SSOConnection{}, invalid("default_tenant_role must be admin, billing or member")
	}
	cfg, err := json.Marshal(c.Config)
	if err != nil {
		return SSOConnection{}, err
	}
	var out SSOConnection
	err = s.tx(ctx, sc.InTenant(c.TenantID), func(tx pgx.Tx) error {
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if out, err = scanSSO(tx.QueryRow(ctx, `INSERT INTO tenant_sso (tenant_id, alias, protocol, display_name, config,
			client_secret, default_tenant_role, version, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING `+ssoCols, c.TenantID, c.Alias, c.Protocol, c.DisplayName, cfg, c.SealedSecret,
			c.DefaultTenantRole, v, uuidOrNil(sc.UserID))); err != nil {
			return err
		}
		return audit(ctx, tx, c.TenantID, "sso.created", ssoTarget(c.TenantID), out)
	})
	return out, err
}

func uuidOrNil(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func (s *Store) GetSSO(ctx context.Context, sc Scope, tenantID uuid.UUID) (SSOConnection, error) {
	var out SSOConnection
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) (err error) {
		out, err = scanSSO(tx.QueryRow(ctx, `SELECT `+ssoCols+` FROM tenant_sso WHERE tenant_id = $1`, tenantID))
		return err
	})
	return out, err
}

func (s *Store) DeleteSSO(ctx context.Context, sc Scope, tenantID uuid.UUID) error {
	return s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		c, err := scanSSO(tx.QueryRow(ctx, `DELETE FROM tenant_sso WHERE tenant_id = $1 RETURNING `+ssoCols, tenantID))
		if err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "sso.deleted", ssoTarget(tenantID), c)
	})
}

// Discovery is where home-realm discovery sends an address.
type Discovery struct {
	TenantSlug string
	Alias      string
}

// DiscoverSSO finds the active tenant that verified the email's domain and has an SSO connection. It reads across
// tenants (operator scope) and returns ErrNotFound otherwise.
func (s *Store) DiscoverSSO(ctx context.Context, email string) (Discovery, error) {
	domain := EmailDomain(email)
	if domain == "" {
		return Discovery{}, ErrNotFound
	}
	var out Discovery
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT t.slug, c.alias FROM tenant_domain d
			JOIN tenant t ON t.id = d.tenant_id AND t.status = 'active'
			JOIN tenant_sso c ON c.tenant_id = d.tenant_id
			WHERE d.domain = $1 AND d.verified_at IS NOT NULL`, domain).Scan(&out.TenantSlug, &out.Alias))
	})
	return out, err
}

// SSOLoginResult is what a sign-in through a tenant's identity provider led to.
type SSOLoginResult struct {
	TenantID   uuid.UUID `json:"tid"`
	TenantSlug string    `json:"tenant"`
	Joined     bool      `json:"joined"` // a membership was created just now (just-in-time)
}

// SSOLogin checks a sign-in through the identity provider with this alias: the asserted email must be in a domain
// the provider's tenant verified, so a tenant's IdP can never sign in someone else's address. With a user id it then
// records the user and makes them a member with the connection's default role and each enabled app's default role
// (just-in-time). Refusals are *TokenRefusal.
func (s *Store) SSOLogin(ctx context.Context, alias string, user UserProfile) (SSOLoginResult, error) {
	var out SSOLoginResult
	var conn SSOConnection
	var status string
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var err error
		if conn, err = scanSSO(tx.QueryRow(ctx, `SELECT `+ssoCols+` FROM tenant_sso WHERE alias = $1`, alias)); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT slug, status FROM tenant WHERE id = $1`, conn.TenantID).
			Scan(&out.TenantSlug, &status)
	})
	if errors.Is(err, ErrNotFound) {
		return out, refuse("unknown_identity_provider", "this identity provider is not connected to an organisation")
	}
	if err != nil {
		return out, err
	}
	out.TenantID = conn.TenantID
	if status != "active" {
		return out, refuse("tenant_inactive", "this organisation is not available")
	}
	domain := EmailDomain(user.Email)
	var verified bool
	err = s.tx(ctx, Scope{TenantID: conn.TenantID}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_domain WHERE tenant_id = $1 AND domain = $2
			AND verified_at IS NOT NULL)`, conn.TenantID, domain).Scan(&verified)
	})
	if err != nil {
		return out, err
	}
	if domain == "" || !verified {
		return out, refuse("domain_not_verified", "this organisation's identity provider may only sign in addresses "+
			"in its verified domains")
	}
	if user.ID == uuid.Nil {
		return out, nil
	}
	user.EmailVerified = true
	u, err := s.UpsertUser(ctx, user)
	if err != nil {
		return out, err
	}
	if u.Status != "active" {
		return out, refuse("user_inactive", "this account is deactivated")
	}
	ctx = WithActor(ctx, Actor{Kind: "user", ID: u.ID, Email: user.Email})
	err = s.tx(ctx, Scope{TenantID: conn.TenantID, UserID: u.ID}, func(tx pgx.Tx) error {
		cur, err := getMember(ctx, tx, conn.TenantID, u.ID, true)
		switch {
		case err == nil && cur.Status == "active":
			return nil
		case err == nil && cur.Status == "deactivated":
			return refuse("member_deactivated", "your membership in this organisation is deactivated")
		case err != nil && err != ErrNotFound:
			return err
		}
		if _, err := addMember(ctx, tx, conn.TenantID, u.ID, conn.DefaultTenantRole); err != nil {
			return err
		}
		out.Joined = true
		return grantDefaults(ctx, tx, conn.TenantID, u.ID, nil)
	})
	return out, err
}

// TenantsRequiringMFA lists the slugs of the active tenants the user is an active member of whose security policy
// requires a second factor. It reads across tenants (operator scope); only the internal API calls it.
func (s *Store) TenantsRequiringMFA(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var out []string
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT t.slug FROM membership m
			JOIN tenant t ON t.id = m.tenant_id AND t.status = 'active'
			JOIN security_policy p ON p.tenant_id = m.tenant_id AND p.require_mfa
			WHERE m.user_id = $1 AND m.status = 'active' ORDER BY t.slug`, userID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if out == nil {
		out = []string{}
	}
	return out, err
}

// GovernsUser decides whether a tenant may act on a member's account-wide state in Keycloak (sessions, second
// factors), which affects every tenant the person belongs to. A company tenant governs an active member when the
// member's email domain is verified by that tenant, or when the member belongs to no other organisation (personal
// tenants do not count). Operators always may; this check is for tenant owners and admins.
func (s *Store) GovernsUser(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	var governs bool
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT t.kind = 'company' AND m.status = 'active' AND (
				EXISTS (SELECT 1 FROM tenant_domain d WHERE d.tenant_id = t.id AND d.verified_at IS NOT NULL
				        AND d.domain = lower(split_part(u.email, '@', 2)))
				OR NOT EXISTS (SELECT 1 FROM membership o JOIN tenant ot ON ot.id = o.tenant_id
				        WHERE o.user_id = u.id AND o.tenant_id <> t.id AND o.status <> 'removed'
				        AND ot.status <> 'deleted' AND ot.kind <> 'personal'))
			FROM membership m JOIN tenant t ON t.id = m.tenant_id JOIN app_user u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND m.user_id = $2`, tenantID, userID).Scan(&governs)
	})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return governs, err
}
