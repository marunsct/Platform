package fga

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Model is an OpenFGA authorisation model in its JSON form (schema 1.1). Conditions and modules are not supported.
type Model struct {
	SchemaVersion   string    `json:"schema_version"`
	TypeDefinitions []TypeDef `json:"type_definitions"`
}

type TypeDef struct {
	Type      string             `json:"type"`
	Relations map[string]Userset `json:"relations,omitempty"`
	Metadata  *Metadata          `json:"metadata,omitempty"`
}

type Metadata struct {
	Relations map[string]RelationMetadata `json:"relations,omitempty"`
}

type RelationMetadata struct {
	DirectlyRelatedUserTypes []RelationRef `json:"directly_related_user_types"`
}

// RelationRef is a type a relation accepts directly: "user", "user:*" (Wildcard) or "group#member" (Relation).
type RelationRef struct {
	Type      string    `json:"type"`
	Relation  string    `json:"relation,omitempty"`
	Wildcard  *struct{} `json:"wildcard,omitempty"`
	Condition string    `json:"condition,omitempty"`
}

// Userset is one node of a relation's rewrite: exactly one field is set.
type Userset struct {
	This            *struct{}       `json:"this,omitempty"`
	ComputedUserset *ObjectRelation `json:"computedUserset,omitempty"`
	TupleToUserset  *TupleToUserset `json:"tupleToUserset,omitempty"`
	Union           *Usersets       `json:"union,omitempty"`
	Intersection    *Usersets       `json:"intersection,omitempty"`
	Difference      *Difference     `json:"difference,omitempty"`
}

type ObjectRelation struct {
	Object   string `json:"object,omitempty"`
	Relation string `json:"relation"`
}

type TupleToUserset struct {
	Tupleset        ObjectRelation `json:"tupleset"`
	ComputedUserset ObjectRelation `json:"computedUserset"`
}

type Usersets struct {
	Child []Userset `json:"child"`
}

type Difference struct {
	Base     Userset `json:"base"`
	Subtract Userset `json:"subtract"`
}

// BaseDSL is Matura's own part of every model: the facts maturad keeps in sync from its database. Apps refer to
// these types but cannot write tuples on them.
const BaseDSL = `model
  schema 1.1

type user

type group
  relations
    define member: [user]

type tenant
  relations
    define owner: [user]
    define admin: [user] or owner
    define billing: [user]
    define member: [user] or admin or billing

type workspace
  relations
    define tenant: [tenant]
    define member: member from tenant
    define admin: admin from tenant

type role
  relations
    define assignee: [user, group#member]
`

// Reserved are the types maturad owns (BaseDSL).
var Reserved = []string{"user", "group", "tenant", "workspace", "role"}

// Base returns Matura's model without any app.
func Base() Model {
	m, err := ParseDSL(BaseDSL)
	if err != nil {
		panic(err)
	}
	return m
}

var (
	typeNameRE     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)
	relationNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,49}$`)
)

// ParseModel reads a manifest's model: a string is the OpenFGA DSL, an object the JSON form. It returns the app's
// own types, validated; definitions of Matura's types are accepted when they add nothing to Matura's own (so the
// app's model also runs in the OpenFGA playground) and are dropped.
func ParseModel(raw json.RawMessage) (Model, error) {
	var m Model
	var dsl string
	if err := json.Unmarshal(raw, &dsl); err == nil {
		if m, err = ParseDSL(dsl); err != nil {
			return m, err
		}
	} else {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		var in struct {
			SchemaVersion   string          `json:"schema_version"`
			TypeDefinitions []TypeDef       `json:"type_definitions"`
			Conditions      json.RawMessage `json:"conditions"`
			ID              string          `json:"id"`
		}
		if err := dec.Decode(&in); err != nil {
			return m, fmt.Errorf("authorization model must be OpenFGA DSL (a string) or its JSON form: %v", err)
		}
		if len(in.Conditions) > 0 && string(in.Conditions) != "{}" && string(in.Conditions) != "null" {
			return m, fmt.Errorf("authorization model conditions are not supported")
		}
		m = Model{SchemaVersion: in.SchemaVersion, TypeDefinitions: in.TypeDefinitions}
	}
	if m.SchemaVersion != "1.1" {
		return m, fmt.Errorf("authorization model schema must be 1.1, got %q", m.SchemaVersion)
	}
	base := Base()
	baseTypes := map[string]TypeDef{}
	for _, t := range base.TypeDefinitions {
		baseTypes[t.Type] = t
	}
	var own []TypeDef
	seen := map[string]bool{}
	for _, t := range m.TypeDefinitions {
		if seen[t.Type] {
			return m, fmt.Errorf("type %q is defined twice", t.Type)
		}
		seen[t.Type] = true
		if b, ok := baseTypes[t.Type]; ok {
			for r := range t.Relations {
				if _, ok := b.Relations[r]; !ok {
					return m, fmt.Errorf("type %q is Matura's (relations %s); it cannot gain relation %q",
						t.Type, strings.Join(relationNames(b), ", "), r)
				}
			}
			continue
		}
		if !typeNameRE.MatchString(t.Type) {
			return m, fmt.Errorf("type %q must be lower-case letters, digits, '_' or '-'", t.Type)
		}
		own = append(own, t)
	}
	if len(own) == 0 {
		return m, fmt.Errorf("authorization model defines no types of the app's own")
	}
	out := Model{SchemaVersion: "1.1", TypeDefinitions: own}
	return out, out.validate(base)
}

func relationNames(t TypeDef) []string {
	out := make([]string, 0, len(t.Relations))
	for r := range t.Relations {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// validate checks that every reference resolves, against the app's types and Matura's.
func (m Model) validate(base Model) error {
	types := map[string]TypeDef{}
	for _, t := range append(slices.Clone(base.TypeDefinitions), m.TypeDefinitions...) {
		types[t.Type] = t
	}
	for _, t := range m.TypeDefinitions {
		for name, us := range t.Relations {
			if !relationNameRE.MatchString(name) {
				return fmt.Errorf("relation %q of %q must be lower-case letters, digits or '_'", name, t.Type)
			}
			var direct []RelationRef
			if t.Metadata != nil {
				direct = t.Metadata.Relations[name].DirectlyRelatedUserTypes
			}
			if err := checkUserset(types, t, name, us, len(direct) > 0); err != nil {
				return err
			}
			for _, d := range direct {
				if d.Condition != "" {
					return fmt.Errorf("%s#%s: conditions are not supported", t.Type, name)
				}
				rt, ok := types[d.Type]
				if !ok {
					return fmt.Errorf("%s#%s accepts unknown type %q", t.Type, name, d.Type)
				}
				if d.Relation != "" {
					if _, ok := rt.Relations[d.Relation]; !ok {
						return fmt.Errorf("%s#%s accepts %s#%s, which %q does not define", t.Type, name, d.Type,
							d.Relation, d.Type)
					}
				}
			}
		}
	}
	return nil
}

func checkUserset(types map[string]TypeDef, t TypeDef, rel string, us Userset, hasDirect bool) error {
	where := t.Type + "#" + rel
	switch {
	case us.This != nil:
		if !hasDirect {
			return fmt.Errorf("%s is directly assignable but lists no types", where)
		}
	case us.ComputedUserset != nil:
		if _, ok := t.Relations[us.ComputedUserset.Relation]; !ok {
			return fmt.Errorf("%s refers to %q, which %q does not define", where, us.ComputedUserset.Relation, t.Type)
		}
	case us.TupleToUserset != nil:
		ts := us.TupleToUserset.Tupleset.Relation
		if _, ok := t.Relations[ts]; !ok {
			return fmt.Errorf("%s uses %q in 'from', which %q does not define", where, ts, t.Type)
		}
		var found bool
		if t.Metadata != nil {
			for _, d := range t.Metadata.Relations[ts].DirectlyRelatedUserTypes {
				if _, ok := types[d.Type].Relations[us.TupleToUserset.ComputedUserset.Relation]; ok {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("%s: no type %s#%s accepts defines %q", where, t.Type, ts,
				us.TupleToUserset.ComputedUserset.Relation)
		}
	case us.Union != nil || us.Intersection != nil:
		set := us.Union
		if set == nil {
			set = us.Intersection
		}
		if len(set.Child) < 2 {
			return fmt.Errorf("%s: a combination needs at least two parts", where)
		}
		for _, c := range set.Child {
			if err := checkUserset(types, t, rel, c, hasDirect); err != nil {
				return err
			}
		}
	case us.Difference != nil:
		if err := checkUserset(types, t, rel, us.Difference.Base, hasDirect); err != nil {
			return err
		}
		return checkUserset(types, t, rel, us.Difference.Subtract, hasDirect)
	default:
		return fmt.Errorf("%s has an empty definition", where)
	}
	return nil
}

// TypeNames lists the types an app model defines.
func (m Model) TypeNames() []string {
	out := make([]string, len(m.TypeDefinitions))
	for i, t := range m.TypeDefinitions {
		out[i] = t.Type
	}
	return out
}

// ForApp is the model maturad writes to OpenFGA for an app: Matura's types plus the app's, each app type renamed
// "<app>.<type>" so apps sharing the store never share a type.
func ForApp(app string, own Model) Model {
	out := Base()
	mine := map[string]bool{}
	for _, t := range own.TypeDefinitions {
		mine[t.Type] = true
	}
	for _, t := range own.TypeDefinitions {
		b, _ := json.Marshal(t)
		var c TypeDef
		_ = json.Unmarshal(b, &c) // deep copy
		c.Type = app + "." + t.Type
		if c.Metadata != nil {
			for r, md := range c.Metadata.Relations {
				for i, d := range md.DirectlyRelatedUserTypes {
					if mine[d.Type] {
						md.DirectlyRelatedUserTypes[i].Type = app + "." + d.Type
					}
				}
				c.Metadata.Relations[r] = md
			}
		}
		out.TypeDefinitions = append(out.TypeDefinitions, c)
	}
	return out
}

// Hash identifies a model's content, so an unchanged model is not written again.
func (m Model) Hash() string {
	b, _ := json.Marshal(m) // maps marshal with sorted keys
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
