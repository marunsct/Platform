package api

import (
	"fmt"
	"strconv"
	"strings"
)

// SCIM filters (RFC 7644 §3.4.2.2), attribute paths (§3.5.2) and PATCH operations (§3.5.2.1–3), in the subset
// identity providers send: `eq` comparisons joined by `and`, value filters in brackets, sub-attributes and
// extension-schema prefixes.

const (
	scimCoreUser   = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimCoreGroup  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimEnterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	scimPatchOp    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimListResp   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorURN   = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// scimCond is one comparison: path[bracket].sub op value. Bracket holds a value filter on a multi-valued
// attribute; a bare bracket (members[value eq "x"]) has no op.
type scimCond struct {
	Attr    string // as written, without a core schema prefix
	Bracket []scimCond
	Sub     string
	Op      string // eq, or "" for a bare bracket
	Value   any    // string, bool, float64 or nil
}

type filterLexer struct {
	s   string
	pos int
}

func (l *filterLexer) skipSpace() {
	for l.pos < len(l.s) && (l.s[l.pos] == ' ' || l.s[l.pos] == '\t') {
		l.pos++
	}
}

// word reads an attribute path, operator or keyword: everything up to a space, bracket, quote or parenthesis.
func (l *filterLexer) word() string {
	l.skipSpace()
	start := l.pos
	for l.pos < len(l.s) && !strings.ContainsRune(" \t[]()\"", rune(l.s[l.pos])) {
		l.pos++
	}
	return l.s[start:l.pos]
}

func (l *filterLexer) peek() byte {
	l.skipSpace()
	if l.pos >= len(l.s) {
		return 0
	}
	return l.s[l.pos]
}

func (l *filterLexer) value() (any, error) {
	if l.peek() == '"' {
		l.pos++
		var b strings.Builder
		for l.pos < len(l.s) {
			c := l.s[l.pos]
			switch {
			case c == '\\' && l.pos+1 < len(l.s):
				b.WriteByte(l.s[l.pos+1])
				l.pos += 2
			case c == '"':
				l.pos++
				return b.String(), nil
			default:
				b.WriteByte(c)
				l.pos++
			}
		}
		return nil, fmt.Errorf("unterminated string")
	}
	w := l.word()
	switch strings.ToLower(w) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}
	if f, err := strconv.ParseFloat(w, 64); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("expected a value, found %q", w)
}

// parseSCIMFilter parses `cond (and cond)*`; `or`, `not`, parentheses and operators other than eq are refused.
func parseSCIMFilter(s string) ([]scimCond, error) {
	l := &filterLexer{s: s}
	conds, err := l.conds(false)
	if err != nil {
		return nil, err
	}
	if l.peek() != 0 {
		return nil, fmt.Errorf("unexpected %q", l.s[l.pos:])
	}
	return conds, nil
}

func (l *filterLexer) conds(inBracket bool) ([]scimCond, error) {
	var out []scimCond
	for {
		c, err := l.cond(inBracket)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		save := l.pos
		w := l.word()
		switch strings.ToLower(w) {
		case "and":
			continue
		case "or", "not":
			return nil, fmt.Errorf("only `and` is supported")
		default:
			l.pos = save
			return out, nil
		}
	}
}

func (l *filterLexer) cond(inBracket bool) (scimCond, error) {
	if l.peek() == '(' {
		return scimCond{}, fmt.Errorf("parentheses are not supported")
	}
	attr := l.word()
	if attr == "" {
		return scimCond{}, fmt.Errorf("expected an attribute")
	}
	c := scimCond{Attr: stripCoreURN(attr)}
	if l.peek() == '[' {
		if inBracket {
			return c, fmt.Errorf("nested value filters are not supported")
		}
		l.pos++
		inner, err := l.conds(true)
		if err != nil {
			return c, err
		}
		if l.peek() != ']' {
			return c, fmt.Errorf("expected ]")
		}
		l.pos++
		c.Bracket = inner
		if l.pos < len(l.s) && l.s[l.pos] == '.' {
			l.pos++
			c.Sub = l.word()
		}
		save := l.pos
		if op := strings.ToLower(l.word()); op != "eq" {
			l.pos = save // a bare value filter: members[value eq "x"]
			return c, nil
		}
		c.Op = "eq"
	} else {
		op := strings.ToLower(l.word())
		switch op {
		case "eq":
		case "pr", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
			return c, fmt.Errorf("operator %q is not supported (only eq)", op)
		default:
			return c, fmt.Errorf("expected an operator after %q", attr)
		}
		c.Op = op
	}
	v, err := l.value()
	if err != nil {
		return c, err
	}
	c.Value = v
	return c, nil
}

func stripCoreURN(attr string) string {
	for _, urn := range []string{scimCoreUser, scimCoreGroup} {
		if len(attr) > len(urn) && strings.EqualFold(attr[:len(urn)+1], urn+":") {
			return attr[len(urn)+1:]
		}
	}
	return attr
}

// matchElem evaluates a value filter on one element of a multi-valued attribute.
func matchElem(elem any, conds []scimCond) bool {
	m, ok := elem.(map[string]any)
	if !ok {
		return false
	}
	for _, c := range conds {
		_, v, found := getCI(m, c.Attr)
		if !found {
			return false
		}
		if !strings.EqualFold(fmt.Sprint(v), fmt.Sprint(c.Value)) {
			return false
		}
	}
	return true
}

// --- attribute paths ----------------------------------------------------------------------------------------------

// scimPath is a PATCH target: a top-level attribute (or an extension schema), an optional value filter on it, and
// up to two sub-attribute names below it.
type scimPath struct {
	Attr   string
	Filter []scimCond
	Rest   []string
}

// extensions are the schemas whose attributes can be addressed as `<urn>:<attr>`.
var scimExtensions = []string{scimEnterprise}

func parseSCIMPath(p string) (scimPath, error) {
	p = strings.TrimSpace(p)
	for _, urn := range scimExtensions {
		if strings.EqualFold(p, urn) {
			return scimPath{Attr: urn}, nil
		}
		if len(p) > len(urn) && strings.EqualFold(p[:len(urn)+1], urn+":") {
			return scimPath{Attr: urn, Rest: strings.Split(p[len(urn)+1:], ".")}, nil
		}
	}
	p = stripCoreURN(p)
	var out scimPath
	if i := strings.IndexByte(p, '['); i >= 0 {
		j := strings.LastIndexByte(p, ']')
		if j < i {
			return out, fmt.Errorf("unbalanced [ in path")
		}
		conds, err := parseSCIMFilter(p[i+1 : j])
		if err != nil {
			return out, err
		}
		out.Attr, out.Filter = p[:i], conds
		if rest := strings.TrimPrefix(p[j+1:], "."); rest != "" {
			out.Rest = []string{rest}
		}
	} else {
		parts := strings.Split(p, ".")
		out.Attr, out.Rest = parts[0], parts[1:]
	}
	if out.Attr == "" || len(out.Rest) > 2 {
		return out, fmt.Errorf("path %q is not supported", p)
	}
	return out, nil
}

// getCI finds a key ignoring case (SCIM attribute names are case-insensitive).
func getCI(m map[string]any, name string) (string, any, bool) {
	if v, ok := m[name]; ok {
		return name, v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return k, v, true
		}
	}
	return name, nil, false
}

func setCI(m map[string]any, name string, v any) {
	k, _, _ := getCI(m, name)
	m[k] = v
}

func deleteCI(m map[string]any, name string) {
	k, _, ok := getCI(m, name)
	if ok {
		delete(m, k)
	}
}

// --- PATCH --------------------------------------------------------------------------------------------------------

type scimPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

type scimPatchRequest struct {
	Schemas    []string             `json:"schemas"`
	Operations []scimPatchOperation `json:"Operations"`
}

// applySCIMPatch applies the operations to a resource in its JSON form. Errors are *scimError.
func applySCIMPatch(res map[string]any, ops []scimPatchOperation) error {
	if len(ops) == 0 {
		return scimErr(400, "invalidValue", "Operations is empty")
	}
	for i, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return scimErr(400, "invalidSyntax", fmt.Sprintf("operation %d: op must be add, replace or remove", i))
		}
		if op.Path == "" {
			if kind == "remove" {
				return scimErr(400, "noTarget", fmt.Sprintf("operation %d: remove needs a path", i))
			}
			obj, ok := op.Value.(map[string]any)
			if !ok {
				return scimErr(400, "invalidValue", fmt.Sprintf("operation %d: without a path the value must be an object", i))
			}
			for k, v := range obj {
				p, err := parseSCIMPath(k)
				if err != nil {
					return scimErr(400, "invalidPath", fmt.Sprintf("operation %d: %v", i, err))
				}
				if err := patchAt(res, kind, p, v); err != nil {
					return err
				}
			}
			continue
		}
		p, err := parseSCIMPath(op.Path)
		if err != nil {
			return scimErr(400, "invalidPath", fmt.Sprintf("operation %d: %v", i, err))
		}
		if err := patchAt(res, kind, p, op.Value); err != nil {
			return err
		}
	}
	return nil
}

func patchAt(res map[string]any, kind string, p scimPath, value any) error {
	if p.Filter != nil {
		return patchFiltered(res, kind, p, value)
	}
	if len(p.Rest) == 0 {
		_, cur, found := getCI(res, p.Attr)
		switch kind {
		case "remove":
			list, isList := cur.([]any)
			items, hasItems := value.([]any)
			if isList && hasItems { // remove the listed values (Entra ID removes group members this way)
				setCI(res, p.Attr, removeValues(list, items))
				return nil
			}
			deleteCI(res, p.Attr)
		case "add":
			if list, ok := cur.([]any); ok && found {
				setCI(res, p.Attr, addValues(list, value))
				return nil
			}
			fallthrough
		default: // replace
			if cm, ok := cur.(map[string]any); ok {
				if vm, ok := value.(map[string]any); ok {
					for k, v := range vm {
						setCI(cm, k, v)
					}
					return nil
				}
			}
			setCI(res, p.Attr, value)
		}
		return nil
	}
	// sub-attribute: create the containers on the way down
	parent := res
	name := p.Attr
	for _, seg := range p.Rest {
		_, cur, _ := getCI(parent, name)
		child, ok := cur.(map[string]any)
		if !ok {
			if kind == "remove" {
				return nil
			}
			child = map[string]any{}
			setCI(parent, name, child)
		}
		parent, name = child, seg
	}
	if kind == "remove" {
		deleteCI(parent, name)
	} else {
		setCI(parent, name, value)
	}
	return nil
}

// patchFiltered handles attr[filter] and attr[filter].sub. Setting a sub-attribute where nothing matches adds an
// element made from the filter (emails[type eq "work"].value on a user with no work email).
func patchFiltered(res map[string]any, kind string, p scimPath, value any) error {
	_, cur, _ := getCI(res, p.Attr)
	list, _ := cur.([]any)
	matched := false
	out := make([]any, 0, len(list))
	for _, e := range list {
		if !matchElem(e, p.Filter) {
			out = append(out, e)
			continue
		}
		matched = true
		switch {
		case kind == "remove" && len(p.Rest) == 0:
			continue // drop the element
		case kind == "remove":
			deleteCI(e.(map[string]any), p.Rest[0])
		case len(p.Rest) == 0:
			if vm, ok := value.(map[string]any); ok {
				for k, v := range vm {
					setCI(e.(map[string]any), k, v)
				}
			}
		default:
			setCI(e.(map[string]any), p.Rest[0], value)
		}
		out = append(out, e)
	}
	if !matched && kind != "remove" {
		elem := map[string]any{}
		for _, c := range p.Filter {
			elem[c.Attr] = c.Value
		}
		if len(p.Rest) == 0 {
			vm, ok := value.(map[string]any)
			if !ok {
				return scimErr(400, "invalidValue", "a value filter without a sub-attribute needs an object value")
			}
			for k, v := range vm {
				elem[k] = v
			}
		} else {
			elem[p.Rest[0]] = value
		}
		out = append(out, elem)
	}
	setCI(res, p.Attr, out)
	return nil
}

// elemValue is the `value` sub-attribute of a multi-valued element, for de-duplication.
func elemValue(e any) (string, bool) {
	m, ok := e.(map[string]any)
	if !ok {
		return "", false
	}
	_, v, found := getCI(m, "value")
	if !found {
		return "", false
	}
	return strings.ToLower(fmt.Sprint(v)), true
}

func addValues(list []any, value any) []any {
	items, ok := value.([]any)
	if !ok {
		items = []any{value}
	}
	seen := map[string]bool{}
	for _, e := range list {
		if v, ok := elemValue(e); ok {
			seen[v] = true
		}
	}
	out := append([]any{}, list...)
	for _, e := range items {
		if v, ok := elemValue(e); ok {
			if seen[v] {
				continue
			}
			seen[v] = true
		}
		out = append(out, e)
	}
	return out
}

func removeValues(list, items []any) []any {
	drop := map[string]bool{}
	for _, e := range items {
		if v, ok := elemValue(e); ok {
			drop[v] = true
		}
	}
	out := []any{}
	for _, e := range list {
		if v, ok := elemValue(e); ok && drop[v] {
			continue
		}
		out = append(out, e)
	}
	return out
}
