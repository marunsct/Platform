package fga

import (
	"fmt"
	"strings"
	"unicode"
)

// ParseDSL reads the OpenFGA modelling language (schema 1.1) into its JSON form. It covers what apps need for
// resource permissions: direct types ([user, user:*, group#member]), computed relations, "x from y", and the
// operators or, and, but not with parentheses. Conditions ("with"), modules and "extend type" are refused.
func ParseDSL(src string) (Model, error) {
	m := Model{}
	var cur *TypeDef
	inRelations := false
	for n, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "#"); i >= 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			line = line[:i] // comment; "group#member" has no space before '#'
		}
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		fail := func(format string, a ...any) (Model, error) {
			return m, fmt.Errorf("authorization model line %d: %s", n+1, fmt.Sprintf(format, a...))
		}
		fields := strings.Fields(text)
		switch fields[0] {
		case "model":
			if len(fields) != 1 {
				return fail("unexpected %q", text)
			}
		case "schema":
			if len(fields) != 2 {
				return fail("schema needs a version")
			}
			m.SchemaVersion = fields[1]
		case "type":
			if len(fields) != 2 {
				return fail("type needs one name")
			}
			m.TypeDefinitions = append(m.TypeDefinitions, TypeDef{Type: fields[1]})
			cur, inRelations = &m.TypeDefinitions[len(m.TypeDefinitions)-1], false
		case "relations":
			if cur == nil || len(fields) != 1 {
				return fail("relations must follow a type")
			}
			inRelations = true
		case "define":
			if cur == nil || !inRelations {
				return fail("define must be inside a type's relations")
			}
			name, expr, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(text, "define")), ":")
			name = strings.TrimSpace(name)
			if !ok || name == "" {
				return fail("expected 'define <relation>: <definition>'")
			}
			if _, dup := cur.Relations[name]; dup {
				return fail("relation %q is defined twice in %q", name, cur.Type)
			}
			p := &exprParser{toks: tokenize(expr)}
			us, err := p.parse()
			if err != nil {
				return fail("%s", err)
			}
			if cur.Relations == nil {
				cur.Relations = map[string]Userset{}
				cur.Metadata = &Metadata{Relations: map[string]RelationMetadata{}}
			}
			cur.Relations[name] = us
			cur.Metadata.Relations[name] = RelationMetadata{DirectlyRelatedUserTypes: nonNilRefs(p.direct)}
		case "condition", "module", "extend":
			return fail("%q is not supported", fields[0])
		default:
			return fail("unexpected %q", text)
		}
	}
	if m.SchemaVersion == "" {
		return m, fmt.Errorf("authorization model needs 'model' and 'schema 1.1'")
	}
	return m, nil
}

func nonNilRefs(r []RelationRef) []RelationRef {
	if r == nil {
		return []RelationRef{}
	}
	return r
}

func tokenize(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			flush()
		case strings.ContainsRune("[](),", r):
			flush()
			out = append(out, string(r))
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

type exprParser struct {
	toks   []string
	pos    int
	direct []RelationRef
	seenDT bool
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) next() string { t := p.peek(); p.pos++; return t }

func (p *exprParser) parse() (Userset, error) {
	us, err := p.expr()
	if err != nil {
		return us, err
	}
	if p.peek() != "" {
		return us, fmt.Errorf("unexpected %q", p.peek())
	}
	return us, nil
}

// expr is term followed by only one kind of operator; mixing needs parentheses, as in OpenFGA.
func (p *exprParser) expr() (Userset, error) {
	first, err := p.term()
	if err != nil {
		return first, err
	}
	switch op := p.peek(); op {
	case "or", "and":
		parts := []Userset{first}
		for p.peek() == op {
			p.next()
			t, err := p.term()
			if err != nil {
				return t, err
			}
			parts = append(parts, t)
		}
		if k := p.peek(); k == "or" || k == "and" || k == "but" {
			return first, fmt.Errorf("mixing operators needs parentheses")
		}
		if op == "or" {
			return Userset{Union: &Usersets{Child: parts}}, nil
		}
		return Userset{Intersection: &Usersets{Child: parts}}, nil
	case "but":
		p.next()
		if p.next() != "not" {
			return first, fmt.Errorf("expected 'but not'")
		}
		sub, err := p.term()
		if err != nil {
			return sub, err
		}
		if k := p.peek(); k == "or" || k == "and" || k == "but" {
			return first, fmt.Errorf("mixing operators needs parentheses")
		}
		return Userset{Difference: &Difference{Base: first, Subtract: sub}}, nil
	}
	return first, nil
}

func (p *exprParser) term() (Userset, error) {
	switch t := p.next(); {
	case t == "":
		return Userset{}, fmt.Errorf("definition ends early")
	case t == "(":
		us, err := p.expr()
		if err != nil {
			return us, err
		}
		if p.next() != ")" {
			return us, fmt.Errorf("missing ')'")
		}
		return us, nil
	case t == "[":
		if p.seenDT {
			return Userset{}, fmt.Errorf("a relation lists its direct types once")
		}
		p.seenDT = true
		for {
			ref := p.next()
			if ref == "" || ref == "]" || ref == "," {
				return Userset{}, fmt.Errorf("expected a type in [...]")
			}
			if p.peek() == "with" {
				return Userset{}, fmt.Errorf("conditions are not supported")
			}
			r, err := parseRef(ref)
			if err != nil {
				return Userset{}, err
			}
			p.direct = append(p.direct, r)
			switch p.next() {
			case ",":
				continue
			case "]":
				return Userset{This: &struct{}{}}, nil
			default:
				return Userset{}, fmt.Errorf("expected ',' or ']'")
			}
		}
	case isIdent(t) && !keywords[t]:
		if p.peek() == "from" {
			p.next()
			ts := p.next()
			if !isIdent(ts) || keywords[ts] {
				return Userset{}, fmt.Errorf("expected a relation after 'from'")
			}
			return Userset{TupleToUserset: &TupleToUserset{Tupleset: ObjectRelation{Relation: ts},
				ComputedUserset: ObjectRelation{Relation: t}}}, nil
		}
		return Userset{ComputedUserset: &ObjectRelation{Relation: t}}, nil
	default:
		return Userset{}, fmt.Errorf("unexpected %q", t)
	}
}

var keywords = map[string]bool{"or": true, "and": true, "but": true, "not": true, "from": true, "with": true}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

func parseRef(s string) (RelationRef, error) {
	if typ, ok := strings.CutSuffix(s, ":*"); ok && isIdent(typ) {
		return RelationRef{Type: typ, Wildcard: &struct{}{}}, nil
	}
	if typ, rel, ok := strings.Cut(s, "#"); ok {
		if !isIdent(typ) || !isIdent(rel) {
			return RelationRef{}, fmt.Errorf("bad type reference %q", s)
		}
		return RelationRef{Type: typ, Relation: rel}, nil
	}
	if !isIdent(s) {
		return RelationRef{}, fmt.Errorf("bad type reference %q", s)
	}
	return RelationRef{Type: s}, nil
}
