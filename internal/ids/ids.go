// Package ids generates identifiers and validates the names users choose.
package ids

import (
	"regexp"

	"github.com/google/uuid"
)

// New returns a UUIDv7: time-ordered, so indexes on it stay compact.
func New() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$`)

// Reserved slugs would collide with routes, Keycloak paths or generated database names.
var reserved = map[string]bool{
	"admin": true, "api": true, "app": true, "apps": true, "auth": true, "internal": true, "login": true,
	"logout": true, "matura": true, "me": true, "operator": true, "postgres": true, "public": true,
	"realms": true, "root": true, "shared": true, "system": true, "template0": true, "template1": true,
	"www": true,
}

// ValidSlug reports whether s may be used as a tenant or app slug. Slugs end up in URLs and in generated
// Postgres names (always quoted), so they are kept to lower-case letters, digits and inner hyphens.
func ValidSlug(s string) bool {
	return slugRE.MatchString(s) && !reserved[s]
}
