package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is the part of an app manifest the checker uses.
type Manifest struct {
	Slug        string `json:"slug"`
	ClientID    string `json:"client_id,omitempty"`
	Permissions []struct {
		Name string `json:"name"`
	} `json:"permissions,omitempty"`
	Roles []struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	} `json:"roles,omitempty"`
	DefaultRole string       `json:"default_role,omitempty"`
	OwnerRole   string       `json:"owner_role,omitempty"`
	Conformance *Conformance `json:"conformance,omitempty"`
}

// Conformance is the manifest's conformance section.
type Conformance struct {
	WebhookPath string     `json:"webhook_path,omitempty"`
	Resources   []Resource `json:"resources"`
}

// Resource is one kind of tenant-owned record the app exposes through its API.
type Resource struct {
	Name   string    `json:"name"`
	Create Endpoint  `json:"create"`
	List   Endpoint  `json:"list"`
	Read   *Endpoint `json:"read,omitempty"`
}

// Endpoint is one call of the app's API. Body is sent as JSON with {{marker}} replaced.
type Endpoint struct {
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	Body       json.RawMessage `json:"body,omitempty"`
	Permission string          `json:"permission,omitempty"`
}

// LoadManifest reads a manifest file (JSON, or YAML by extension) and validates its conformance section.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		var v any
		if err := yaml.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("manifest %s: %w", path, err)
		}
		if raw, err = json.Marshal(v); err != nil {
			return nil, fmt.Errorf("manifest %s: %w", path, err)
		}
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return m, nil
}

// ParseManifest decodes a JSON manifest, fills defaults and validates its conformance section.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Slug == "" {
		return nil, errors.New("slug is missing")
	}
	if m.Conformance == nil || len(m.Conformance.Resources) == 0 {
		return nil, errors.New(`conformance.resources is missing: list at least one resource with create and list endpoints`)
	}
	if p := m.Conformance.WebhookPath; p != "" && !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("conformance.webhook_path %q must start with /", p)
	}
	for i := range m.Conformance.Resources {
		r := &m.Conformance.Resources[i]
		if r.Name == "" {
			r.Name = fmt.Sprintf("resource%d", i+1)
		}
		if err := r.Create.fill("POST"); err != nil {
			return nil, fmt.Errorf("conformance resource %q create: %w", r.Name, err)
		}
		if err := r.List.fill("GET"); err != nil {
			return nil, fmt.Errorf("conformance resource %q list: %w", r.Name, err)
		}
		if r.Read != nil {
			if err := r.Read.fill("GET"); err != nil {
				return nil, fmt.Errorf("conformance resource %q read: %w", r.Name, err)
			}
			if !strings.Contains(r.Read.Path, "{id}") {
				return nil, fmt.Errorf("conformance resource %q read: path %q has no {id}", r.Name, r.Read.Path)
			}
		}
	}
	return &m, nil
}

func (e *Endpoint) fill(method string) error {
	if e.Path == "" || !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("path %q must start with /", e.Path)
	}
	if e.Method == "" {
		e.Method = method
	}
	e.Method = strings.ToUpper(e.Method)
	if len(e.Body) > 0 && string(e.Body) == "null" {
		e.Body = nil
	}
	return nil
}

// Audience is the token audience the app expects: its client id, which defaults to its slug.
func (m *Manifest) Audience() string {
	if m.ClientID != "" {
		return m.ClientID
	}
	return m.Slug
}

// AllPermissions is every concrete permission the manifest names (catalogue, roles and conformance endpoints),
// sorted, without "*". A token carrying them can do everything the checker asks.
func (m *Manifest) AllPermissions() []string {
	set := map[string]bool{}
	for _, p := range m.Permissions {
		set[p.Name] = true
	}
	for _, r := range m.Roles {
		for _, p := range r.Permissions {
			set[p] = true
		}
	}
	if m.Conformance != nil {
		for _, r := range m.Conformance.Resources {
			set[r.Create.Permission] = true
			set[r.List.Permission] = true
			if r.Read != nil {
				set[r.Read.Permission] = true
			}
		}
	}
	delete(set, "")
	delete(set, "*")
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// role is the app role the test users are granted.
func (m *Manifest) role() string {
	switch {
	case m.OwnerRole != "":
		return m.OwnerRole
	case m.DefaultRole != "":
		return m.DefaultRole
	case len(m.Roles) > 0:
		return m.Roles[0].Name
	}
	return "member"
}
