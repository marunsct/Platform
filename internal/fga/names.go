package fga

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Namespace translates between what an app says ("document:d1", "user:<id>", "role:editor") and what is stored in
// the installation's single OpenFGA store, where every app and tenant share one tuple space:
//
//	type:   Matura's types keep their name; the app's types become "<app>.<type>"
//	object: "<tenant>/<id>"; for role objects "<tenant>/<app>/<id>" (roles are per app)
//
// Every stored id starts with the tenant, so no tuple an app writes in one tenant can name an object or subject of
// another tenant, and a check or listing in one tenant can only reach that tenant's tuples. Only "user:*" (any user)
// is not prefixed; it can only grant access to objects that already belong to the tenant.
type Namespace struct {
	App    string
	Tenant uuid.UUID
	Types  []string // the app's own types (from its manifest's model)
}

var (
	idRE  = regexp.MustCompile(`^[^\s#:*][^\s#:]{0,199}$`)
	relRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,49}$`)
)

func (n Namespace) storedType(t string) (string, error) {
	switch {
	case slices.Contains(Reserved, t):
		return t, nil
	case slices.Contains(n.Types, t):
		return n.App + "." + t, nil
	}
	return "", fmt.Errorf("unknown type %q", t)
}

func (n Namespace) prefix(t string) string {
	if t == "role" {
		return n.Tenant.String() + "/" + n.App + "/"
	}
	return n.Tenant.String() + "/"
}

// Object maps "type:id" to its stored form.
func (n Namespace) Object(s string) (string, error) {
	t, id, ok := strings.Cut(s, ":")
	if !ok || !idRE.MatchString(id) {
		return "", fmt.Errorf("object %q must be type:id", s)
	}
	st, err := n.storedType(t)
	if err != nil {
		return "", err
	}
	return st + ":" + n.prefix(t) + id, nil
}

// AppObject is Object for an object the app may write tuples on: one of its own types.
func (n Namespace) AppObject(s string) (string, error) {
	t, _, _ := strings.Cut(s, ":")
	if slices.Contains(Reserved, t) {
		return "", fmt.Errorf("%q objects are kept by Matura from its own records; apps cannot write them", t)
	}
	return n.Object(s)
}

// User maps a subject, "type:id", "type:id#relation" or "type:*", to its stored form.
func (n Namespace) User(s string) (string, error) {
	obj, rel, hasRel := strings.Cut(s, "#")
	if hasRel && !relRE.MatchString(rel) {
		return "", fmt.Errorf("user %q has a bad relation", s)
	}
	if t, ok := strings.CutSuffix(obj, ":*"); ok && !hasRel {
		st, err := n.storedType(t)
		if err != nil {
			return "", err
		}
		return st + ":*", nil
	}
	o, err := n.Object(obj)
	if err != nil {
		return "", fmt.Errorf("user %q must be type:id, type:id#relation or type:*", s)
	}
	if hasRel {
		o += "#" + rel
	}
	return o, nil
}

// Type maps an object type for listing.
func (n Namespace) Type(t string) (string, error) { return n.storedType(t) }

// Relation checks a relation name.
func Relation(r string) error {
	if !relRE.MatchString(r) {
		return fmt.Errorf("relation %q must be lower-case letters, digits or '_'", r)
	}
	return nil
}

// FromObject maps a stored object back to what the app says; ok is false for one outside this app and tenant.
func (n Namespace) FromObject(s string) (string, bool) {
	st, id, ok := strings.Cut(s, ":")
	if !ok {
		return "", false
	}
	t := st
	if a, rest, ok := strings.Cut(st, "."); ok {
		if a != n.App {
			return "", false
		}
		t = rest
	} else if !slices.Contains(Reserved, st) {
		return "", false
	}
	id, ok = strings.CutPrefix(id, n.prefix(t))
	if !ok {
		return "", false
	}
	return t + ":" + id, true
}

// Key maps a tuple the app wrote or asked about.
func (n Namespace) Key(user, relation, object string, write bool) (TupleKey, error) {
	var k TupleKey
	var err error
	if write {
		k.Object, err = n.AppObject(object)
	} else {
		k.Object, err = n.Object(object)
	}
	if err != nil {
		return k, err
	}
	if err := Relation(relation); err != nil {
		return k, err
	}
	k.Relation = relation
	k.User, err = n.User(user)
	return k, err
}

// --- Matura's own facts -----------------------------------------------------------------------------------------

func tenantPrefix(tid uuid.UUID) string { return tid.String() + "/" }

// TenantObject is the stored tenant object.
func TenantObject(tid uuid.UUID) string { return "tenant:" + tenantPrefix(tid) + tid.String() }

// UserSubject is the stored user, as members and grantees.
func UserSubject(tid, uid uuid.UUID) string { return "user:" + tenantPrefix(tid) + uid.String() }

// GroupMembers is the stored "everyone in the group" subject.
func GroupMembers(tid, gid uuid.UUID) string {
	return "group:" + tenantPrefix(tid) + gid.String() + "#member"
}

// WorkspaceObject is the stored workspace object.
func WorkspaceObject(tid, wid uuid.UUID) string {
	return "workspace:" + tenantPrefix(tid) + wid.String()
}

// RoleObject is the stored role object for a grant: "role:<name>" for the whole tenant, "role:<name>@<workspace>"
// in one workspace, as the app names it.
func RoleObject(tid uuid.UUID, app, role string, wid *uuid.UUID) string {
	id := role
	if wid != nil {
		id += "@" + wid.String()
	}
	return "role:" + tenantPrefix(tid) + app + "/" + id
}

// InTenant reports whether a stored object belongs to the tenant.
func InTenant(object string, tid uuid.UUID) bool {
	_, id, _ := strings.Cut(object, ":")
	return strings.HasPrefix(id, tenantPrefix(tid))
}

// TenantRoles are the tenant relations maturad writes from memberships.
var TenantRoles = []string{"owner", "admin", "billing", "member"}
