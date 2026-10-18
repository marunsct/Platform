package store

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"

	"github.com/marunsct/Platform/internal/ids"
)

// Manifest is the part of an app manifest maturad stores and enforces (doc 06 §1, technical specification §7.2).
type Manifest struct {
	Slug        string          `json:"slug"`
	Name        string          `json:"name"`
	ClientID    string          `json:"client_id,omitempty"`
	Auth        ManifestAuth    `json:"auth"`
	Permissions []PermissionDef `json:"permissions,omitempty"` // the catalogue; derived from roles when empty
	Roles       []RoleDef       `json:"roles,omitempty"`       // starter roles, editable in Matura (ADR 0008)
	DefaultRole string          `json:"default_role"`
	OwnerRole   string          `json:"owner_role,omitempty"` // role tenant owners and admins get implicitly
	Tenancy     Tenancy         `json:"tenancy"`
	// Conformance is read by matura-conformance (docs/guide/conformance.md); maturad keeps it but does not use it.
	Conformance json.RawMessage `json:"conformance,omitempty"`
}

type ManifestAuth struct {
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	PublicClient           bool     `json:"public_client"`
	// Resources are the app's protected-resource identifiers (RFC 9728), e.g. its MCP server's URL: an agent that
	// asks Keycloak for a token with resource=<one of them> gets a token for this app (TS15).
	Resources []string `json:"resources,omitempty"`
}

type PermissionDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
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

// validateRole checks a role name and that its permissions are well formed and, when catalogue is given, in it.
func validateRole(name string, perms []string, catalogue map[string]bool) error {
	if !roleNameRE.MatchString(name) {
		return invalid("role name %q must be lower-case letters, digits, '_' or '-'", name)
	}
	for _, p := range perms {
		if !permissionRE.MatchString(p) {
			return invalid("permission %q of role %q must look like resource.action", p, name)
		}
		if catalogue != nil && p != "*" && !catalogue[p] {
			return invalid("permission %q is not in the app's permissions", p)
		}
	}
	return nil
}

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
	catalogue := map[string]bool{}
	for _, p := range m.Permissions {
		if p.Name == "*" || !permissionRE.MatchString(p.Name) {
			return invalid("permission %q must look like resource.action", p.Name)
		}
		if catalogue[p.Name] {
			return invalid("permission %q is listed twice", p.Name)
		}
		catalogue[p.Name] = true
	}
	derive := len(m.Permissions) == 0
	seen := map[string]bool{}
	for _, r := range m.Roles {
		if err := validateRole(r.Name, r.Permissions, nil); err != nil {
			return err
		}
		if seen[r.Name] {
			return invalid("role %q is listed twice", r.Name)
		}
		seen[r.Name] = true
		for _, p := range r.Permissions {
			switch {
			case p == "*":
			case derive && !catalogue[p]:
				catalogue[p] = true
				m.Permissions = append(m.Permissions, PermissionDef{Name: p})
			case !catalogue[p]:
				return invalid("role %q uses permission %q, which is not in the app's permissions", r.Name, p)
			}
		}
	}
	if len(m.Permissions) == 0 {
		return invalid("an app needs at least one permission its code checks")
	}
	// default and owner roles may also be roles created in Matura; ApplyApp checks those against the database
	if len(m.Roles) > 0 && m.DefaultRole != "" && !seen[m.DefaultRole] {
		return invalid("default_role %q is not one of the app's roles", m.DefaultRole)
	}
	if len(m.Roles) > 0 && m.OwnerRole != "" && !seen[m.OwnerRole] {
		return invalid("owner_role %q is not one of the app's roles", m.OwnerRole)
	}
	for _, r := range m.Auth.Resources {
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Fragment != "" {
			return invalid("auth resource %q must be an absolute http(s) URL without a fragment", r)
		}
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
