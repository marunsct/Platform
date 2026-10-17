package matura

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Claims are the claims of a verified Matura access token (contract §2). Raw keeps every claim as decoded.
type Claims struct {
	Issuer          string   // iss
	Subject         string   // sub: the user id
	Audience        []string // aud
	ExpiresAt       int64    // exp, Unix seconds
	NotBefore       int64    // nbf, 0 when absent
	IssuedAt        int64    // iat, 0 when absent
	AuthorizedParty string   // azp
	ClientID        string   // client_id (service accounts)
	Email           string
	EmailVerified   bool
	Name            string
	TenantID        string           // tid
	Tenant          string           // tenant: the tenant's slug
	WorkspaceID     string           // wid
	TenantRoles     []string         // troles: owner, admin, billing, member
	Roles           []string         // roles: this app's roles
	Perms           []string         // perms: what the roles allow; "*" allows everything
	PermsRef        string           // perms_ref: set instead of perms when there are too many
	Versions        map[string]int64 // ver: {u, m, t}
	PlacementMode   string           // pmode: shared, schema or database
	ACR             string
	AMR             []string
	SessionID       string // sid
	Raw             map[string]any
}

func claimsFrom(raw map[string]any) *Claims {
	c := &Claims{
		Issuer: str(raw["iss"]), Subject: str(raw["sub"]), Audience: strs(raw["aud"]),
		ExpiresAt: num(raw["exp"]), NotBefore: num(raw["nbf"]), IssuedAt: num(raw["iat"]),
		AuthorizedParty: str(raw["azp"]), ClientID: str(raw["client_id"]),
		Email: str(raw["email"]), EmailVerified: raw["email_verified"] == true, Name: str(raw["name"]),
		TenantID: str(raw["tid"]), Tenant: str(raw["tenant"]), WorkspaceID: str(raw["wid"]),
		TenantRoles: strs(raw["troles"]), Roles: strs(raw["roles"]), Perms: strs(raw["perms"]),
		PermsRef: str(raw["perms_ref"]), Versions: map[string]int64{}, PlacementMode: str(raw["pmode"]),
		ACR: str(raw["acr"]), AMR: strs(raw["amr"]), SessionID: str(raw["sid"]), Raw: raw,
	}
	if s, ok := raw["aud"].(string); ok {
		c.Audience = []string{s}
	}
	if ver, ok := raw["ver"].(map[string]any); ok {
		for k, v := range ver {
			c.Versions[k] = num(v)
		}
	}
	return c
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return fmt.Sprint(int64(x))
	default:
		return fmt.Sprint(x)
	}
}

func strs(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, str(x))
	}
	return out
}

func num(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}

// Principal is who is calling and what they may do, read from a verified Matura access token.
//
// Apps check Permissions (the token's perms), never role names: roles are defined and edited in Matura, permissions
// are what the app's code declares (ADR 0008). Absent claims are empty strings.
type Principal struct {
	UserID        string
	TenantID      string
	TenantSlug    string
	WorkspaceID   string
	TenantRoles   []string
	Roles         []string
	Permissions   []string
	PermsRef      string
	Email         string
	EmailVerified bool
	Name          string
	Versions      map[string]int64
	PlacementMode string
	MFA           bool
	SessionID     string
	ClientID      string
	IsService     bool
	Claims        *Claims
}

// PrincipalFromClaims builds a principal with the same rules as the Python and TypeScript SDKs.
func PrincipalFromClaims(c *Claims) *Principal {
	_, hasClientID := c.Raw["client_id"]
	_, hasEmail := c.Raw["email"]
	client := c.AuthorizedParty
	if client == "" {
		client = c.ClientID
	}
	return &Principal{
		UserID: c.Subject, TenantID: c.TenantID, TenantSlug: c.Tenant, WorkspaceID: c.WorkspaceID,
		TenantRoles: c.TenantRoles, Roles: c.Roles, Permissions: c.Perms, PermsRef: c.PermsRef,
		Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name, Versions: c.Versions,
		PlacementMode: c.PlacementMode,
		MFA: slices.Contains(c.AMR, "mfa") || slices.Contains(c.AMR, "otp") || slices.Contains(c.AMR, "hwk") ||
			c.ACR == "2" || c.ACR == "3",
		SessionID: c.SessionID, ClientID: client, IsService: hasClientID && !hasEmail, Claims: c,
	}
}

// Has reports whether the token grants permission (or "*"). With PermsRef set, call Expand first.
func (p *Principal) Has(permission string) bool {
	return slices.Contains(p.Permissions, "*") || slices.Contains(p.Permissions, permission)
}

// HasRole reports whether the caller has any of this app's roles.
func (p *Principal) HasRole(roles ...string) bool {
	return slices.ContainsFunc(roles, func(r string) bool { return slices.Contains(p.Roles, r) })
}

// HasTenantRole reports whether the caller has any of the tenant roles (owner, admin, billing, member).
func (p *Principal) HasTenantRole(roles ...string) bool {
	return slices.ContainsFunc(roles, func(r string) bool { return slices.Contains(p.TenantRoles, r) })
}

// RequirePermission returns an error wrapping ErrForbidden unless the principal has every permission.
func (p *Principal) RequirePermission(permissions ...string) error {
	var missing []string
	for _, perm := range permissions {
		if !p.Has(perm) {
			missing = append(missing, perm)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: you need the permission %s; ask a tenant admin for a role that includes it",
			ErrForbidden, strings.Join(missing, ", "))
	}
	return nil
}

// RequireRole returns an error wrapping ErrForbidden unless the principal has one of this app's roles.
// Prefer RequirePermission: roles are edited in Matura, permissions are what the code declares.
func (p *Principal) RequireRole(roles ...string) error {
	if !p.HasRole(roles...) {
		return fmt.Errorf("%w: you need one of the roles %s", ErrForbidden, strings.Join(roles, ", "))
	}
	return nil
}

// RequireTenantRole returns an error wrapping ErrForbidden unless the principal has one of the tenant roles.
func (p *Principal) RequireTenantRole(roles ...string) error {
	if !p.HasTenantRole(roles...) {
		return fmt.Errorf("%w: you need to be %s of this organisation", ErrForbidden, strings.Join(roles, " or "))
	}
	return nil
}

// RequireTenant returns an error wrapping ErrForbidden unless the token is for a tenant.
func (p *Principal) RequireTenant() error {
	if p.TenantID == "" {
		return fmt.Errorf("%w: choose an organisation first", ErrForbidden)
	}
	return nil
}

// Expand fills Permissions from the app's role table when the token carried perms_ref (over 40 permissions).
func (p *Principal) Expand(rolePermissions map[string][]string) *Principal {
	if p.PermsRef == "" {
		return p
	}
	set := map[string]bool{}
	for _, r := range p.Roles {
		for _, perm := range rolePermissions[r] {
			set[perm] = true
		}
	}
	out := make([]string, 0, len(set))
	if set["*"] {
		out = append(out, "*")
	} else {
		for perm := range set {
			out = append(out, perm)
		}
		sort.Strings(out)
	}
	cp := *p
	cp.Permissions, cp.PermsRef = out, ""
	return &cp
}
