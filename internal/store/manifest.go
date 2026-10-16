package store

import (
	"regexp"
	"slices"

	"github.com/marunsct/Platform/internal/ids"
)

// Manifest is the part of an app manifest maturad stores and enforces (doc 06 §1, technical specification §7.2).
type Manifest struct {
	Slug        string       `json:"slug"`
	Name        string       `json:"name"`
	ClientID    string       `json:"client_id,omitempty"`
	Auth        ManifestAuth `json:"auth"`
	Roles       []RoleDef    `json:"roles"`
	DefaultRole string       `json:"default_role"`
	OwnerRole   string       `json:"owner_role,omitempty"` // role tenant owners and admins get implicitly
	Tenancy     Tenancy      `json:"tenancy"`
}

type ManifestAuth struct {
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	PublicClient           bool     `json:"public_client"`
}

type RoleDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

type Tenancy struct {
	WorkspaceScoped bool             `json:"workspace_scoped"`
	Modes           []string         `json:"modes"`
	Managers        []string         `json:"managers"`
	Default         PlacementDefault `json:"default"`
}

type PlacementDefault struct {
	Mode    string `json:"mode"`
	Manager string `json:"manager"`
}

var (
	roleNameRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)
	permissionRE = regexp.MustCompile(`^(\*|[a-z][a-z0-9_-]*(\.[a-z0-9_*-]+)*)$`)
	allModes     = []string{"shared", "schema", "database"}
	allManagers  = []string{"app", "platform"}
)

// Normalize fills defaults and validates. Errors are InvalidError with a message for the app developer.
func (m *Manifest) Normalize() error {
	if !ids.ValidSlug(m.Slug) {
		return invalid("slug %q must be 3-40 lower-case letters, digits or inner hyphens, and not reserved", m.Slug)
	}
	if m.Name == "" {
		m.Name = m.Slug
	}
	if m.ClientID == "" {
		m.ClientID = m.Slug
	}
	if len(m.Roles) == 0 {
		return invalid("an app needs at least one role")
	}
	seen := map[string]bool{}
	for _, r := range m.Roles {
		if !roleNameRE.MatchString(r.Name) {
			return invalid("role name %q must be lower-case letters, digits, '_' or '-'", r.Name)
		}
		if seen[r.Name] {
			return invalid("role %q is listed twice", r.Name)
		}
		seen[r.Name] = true
		for _, p := range r.Permissions {
			if !permissionRE.MatchString(p) {
				return invalid("permission %q of role %q must look like resource.action", p, r.Name)
			}
		}
	}
	if !seen[m.DefaultRole] {
		return invalid("default_role %q is not one of the app's roles", m.DefaultRole)
	}
	if m.OwnerRole != "" && !seen[m.OwnerRole] {
		return invalid("owner_role %q is not one of the app's roles", m.OwnerRole)
	}
	t := &m.Tenancy
	if len(t.Modes) == 0 {
		t.Modes = []string{"shared"}
	}
	if len(t.Managers) == 0 {
		t.Managers = []string{"app"}
	}
	for _, mode := range t.Modes {
		if !slices.Contains(allModes, mode) {
			return invalid("tenancy mode %q must be one of shared, schema, database", mode)
		}
	}
	for _, mg := range t.Managers {
		if !slices.Contains(allManagers, mg) {
			return invalid("tenancy manager %q must be app or platform", mg)
		}
	}
	if t.Default.Mode == "" {
		t.Default.Mode = t.Modes[0]
	}
	if t.Default.Manager == "" {
		t.Default.Manager = t.Managers[0]
	}
	if !slices.Contains(t.Modes, t.Default.Mode) || !slices.Contains(t.Managers, t.Default.Manager) {
		return invalid("tenancy default must use one of the listed modes and managers")
	}
	return nil
}
