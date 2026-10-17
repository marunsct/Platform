package store

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SecurityPolicy is a tenant's security settings (TS9). maturad enforces AllowedEmailDomains on invitations and
// IPAllowlist on tenant API calls; Keycloak enforces RequireMFA and the session limits.
type SecurityPolicy struct {
	TenantID            uuid.UUID      `json:"tenant_id"`
	RequireMFA          bool           `json:"require_mfa"`
	SessionMaxAge       *int           `json:"session_max_age"` // seconds; null: installation default
	IdleTimeout         *int           `json:"idle_timeout"`    // seconds; null: installation default
	AllowedEmailDomains []string       `json:"allowed_email_domains"`
	IPAllowlist         []netip.Prefix `json:"ip_allowlist"`
	Version             int64          `json:"version"`
	UpdatedAt           *time.Time     `json:"updated_at"`
}

// AllowsIP reports whether a client address may call the tenant's API. An empty list allows every address.
func (p SecurityPolicy) AllowsIP(ip netip.Addr) bool {
	if len(p.IPAllowlist) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, n := range p.IPAllowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowsEmail reports whether an address is in one of the allowed domains (or a subdomain of one).
func (p SecurityPolicy) AllowsEmail(email string) bool {
	if len(p.AllowedEmailDomains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	domain := strings.ToLower(email[at+1:])
	for _, d := range p.AllowedEmailDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Normalize checks a policy and puts it in canonical form: lower-case unique domains, masked unique prefixes.
func (p *SecurityPolicy) Normalize() error {
	if p.SessionMaxAge != nil && (*p.SessionMaxAge < 300 || *p.SessionMaxAge > 90*24*3600) {
		return invalid("session_max_age must be between 300 seconds and 90 days")
	}
	if p.IdleTimeout != nil {
		if *p.IdleTimeout < 60 || *p.IdleTimeout > 30*24*3600 {
			return invalid("idle_timeout must be between 60 seconds and 30 days")
		}
		if p.SessionMaxAge != nil && *p.IdleTimeout > *p.SessionMaxAge {
			return invalid("idle_timeout cannot be longer than session_max_age")
		}
	}
	if len(p.AllowedEmailDomains) > 100 || len(p.IPAllowlist) > 100 {
		return invalid("at most 100 email domains and 100 address ranges")
	}
	domains := []string{}
	for _, d := range p.AllowedEmailDomains {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "@")
		if !domainRE.MatchString(d) {
			return invalid("%q is not a domain name", d)
		}
		if !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	p.AllowedEmailDomains = domains
	nets := []netip.Prefix{}
	for _, n := range p.IPAllowlist {
		n = n.Masked()
		if !slices.Contains(nets, n) {
			nets = append(nets, n)
		}
	}
	p.IPAllowlist = nets
	return nil
}

func scanPolicy(row pgx.Row, tenantID uuid.UUID) (SecurityPolicy, error) {
	p := SecurityPolicy{TenantID: tenantID}
	err := row.Scan(&p.RequireMFA, &p.SessionMaxAge, &p.IdleTimeout, &p.AllowedEmailDomains, &p.IPAllowlist,
		&p.Version, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecurityPolicy{TenantID: tenantID, AllowedEmailDomains: []string{}, IPAllowlist: []netip.Prefix{}}, nil
	}
	return p, mapErr(err)
}

const policyCols = `require_mfa, session_max_age, idle_timeout, allowed_email_domains, ip_allowlist, version, updated_at`

func getPolicy(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (SecurityPolicy, error) {
	return scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM security_policy WHERE tenant_id = $1`, tenantID), tenantID)
}

// SecurityPolicy returns the tenant's policy, or the default (nothing enforced) when none was set.
func (s *Store) SecurityPolicy(ctx context.Context, sc Scope, tenantID uuid.UUID) (SecurityPolicy, error) {
	var out SecurityPolicy
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) (err error) {
		out, err = getPolicy(ctx, tx, tenantID)
		return err
	})
	return out, err
}

// PutSecurityPolicy replaces the tenant's policy. ifVersion 0 skips the version check.
func (s *Store) PutSecurityPolicy(ctx context.Context, sc Scope, tenantID uuid.UUID, p SecurityPolicy, ifVersion int64) (SecurityPolicy, error) {
	if err := p.Normalize(); err != nil {
		return SecurityPolicy{}, err
	}
	var out SecurityPolicy
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		cur, err := getPolicy(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if ifVersion != 0 && ifVersion != cur.Version {
			return ErrVersion
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if out, err = scanPolicy(tx.QueryRow(ctx, `INSERT INTO security_policy (tenant_id, require_mfa, session_max_age,
			idle_timeout, allowed_email_domains, ip_allowlist, version) VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id) DO UPDATE SET require_mfa = EXCLUDED.require_mfa,
				session_max_age = EXCLUDED.session_max_age, idle_timeout = EXCLUDED.idle_timeout,
				allowed_email_domains = EXCLUDED.allowed_email_domains, ip_allowlist = EXCLUDED.ip_allowlist,
				version = EXCLUDED.version, updated_at = now()
			RETURNING `+policyCols, tenantID, p.RequireMFA, p.SessionMaxAge, p.IdleTimeout, p.AllowedEmailDomains,
			p.IPAllowlist, v), tenantID); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "security_policy.updated", "tenants/"+tenantID.String()+"/security-policy",
			map[string]any{"before": cur, "after": out})
	})
	return out, err
}
