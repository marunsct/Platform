// Package fgatest is an in-memory stand-in for OpenFGA's HTTP API, for tests: stores, models, writes with ignore
// semantics, reads, and checks evaluated against the model (direct types, wildcards, usersets, computed relations,
// "from", or, and, but not). It is not a full OpenFGA: no conditions, no pagination limits.
package fgatest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/marunsct/Platform/internal/fga"
)

type store struct {
	name   string
	models map[string]fga.Model
	latest string
	tuples map[fga.TupleKey]bool
}

// Server is a fake OpenFGA.
type Server struct {
	*httptest.Server
	mu     sync.Mutex
	stores map[string]*store
	n      int
	down   bool
}

// SetDown makes every request fail with 503 (true) or work again (false).
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// New starts a fake OpenFGA that stops with the test.
func New(t *testing.T) *Server {
	s := &Server{stores: map[string]*store{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Wipe forgets every store, like an OpenFGA with the memory datastore that restarted.
func (s *Server) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stores = map[string]*store{}
}

// Tuples returns every tuple of every store, sorted, as "object#relation@user".
func (s *Server) Tuples() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, st := range s.stores {
		for k := range st.tuples {
			out = append(out, k.Object+"#"+k.Relation+"@"+k.User)
		}
	}
	sort.Strings(out)
	return out
}

// Has reports whether any store holds the tuple.
func (s *Server) Has(user, relation, object string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.stores {
		if st.tuples[fga.TupleKey{User: user, Relation: relation, Object: object}] {
			return true
		}
	}
	return false
}

func (s *Server) id() string {
	s.n++
	return fmt.Sprintf("01FAKE%020d", s.n)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		fail(w, http.StatusServiceUnavailable, "unavailable", "down")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if parts[0] != "stores" {
		fail(w, http.StatusNotFound, "not_found", "no route")
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			var list []map[string]string
			for id, st := range s.stores {
				list = append(list, map[string]string{"id": id, "name": st.name, "created_at": id})
			}
			ok(w, map[string]any{"stores": list, "continuation_token": ""})
		case http.MethodPost:
			var in struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			id := s.id()
			s.stores[id] = &store{name: in.Name, models: map[string]fga.Model{}, tuples: map[fga.TupleKey]bool{}}
			ok(w, map[string]string{"id": id, "name": in.Name})
		}
		return
	}
	st := s.stores[parts[1]]
	if st == nil {
		fail(w, http.StatusNotFound, "store_id_not_found", "Store ID not found")
		return
	}
	if len(parts) == 2 {
		ok(w, map[string]string{"id": parts[1], "name": st.name})
		return
	}
	var body struct {
		Model    string        `json:"authorization_model_id"`
		TupleKey *fga.TupleKey `json:"tuple_key"`
		Writes   *struct {
			TupleKeys []fga.TupleKey `json:"tuple_keys"`
		}
		Deletes *struct {
			TupleKeys []fga.TupleKey `json:"tuple_keys"`
		}
		Contextual *struct {
			TupleKeys []fga.TupleKey `json:"tuple_keys"`
		} `json:"contextual_tuples"`
		Checks []struct {
			TupleKey      fga.TupleKey `json:"tuple_key"`
			CorrelationID string       `json:"correlation_id"`
			Contextual    *struct {
				TupleKeys []fga.TupleKey `json:"tuple_keys"`
			} `json:"contextual_tuples"`
		}
		User, Relation, Type string
		Object               *struct{ Type, ID string }
		UserFilters          []struct{ Type string } `json:"user_filters"`
	}
	if parts[2] == "authorization-models" {
		var m fga.Model
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			fail(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		id := s.id()
		st.models[id], st.latest = m, id
		ok(w, map[string]string{"authorization_model_id": id})
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	mid := body.Model
	if mid == "" {
		mid = st.latest
	}
	m, found := st.models[mid]
	if !found && parts[2] != "read" {
		fail(w, http.StatusBadRequest, "authorization_model_not_found", "Authorization Model '"+mid+"' not found")
		return
	}
	ev := &evaluator{m: m, tuples: st.tuples}
	switch parts[2] {
	case "write":
		if body.Writes != nil {
			for _, k := range body.Writes.TupleKeys {
				if err := ev.valid(k); err != nil {
					fail(w, http.StatusBadRequest, "validation_error", err.Error())
					return
				}
			}
		}
		if body.Deletes != nil {
			for _, k := range body.Deletes.TupleKeys {
				delete(st.tuples, k)
			}
		}
		if body.Writes != nil {
			for _, k := range body.Writes.TupleKeys {
				st.tuples[k] = true
			}
		}
		ok(w, map[string]any{})
	case "read":
		var out []map[string]any
		for k := range st.tuples {
			if body.TupleKey == nil || (k.Object == body.TupleKey.Object && (body.TupleKey.User == "" || k.User == body.TupleKey.User)) {
				out = append(out, map[string]any{"key": k})
			}
		}
		ok(w, map[string]any{"tuples": out, "continuation_token": ""})
	case "check":
		ev.extra = contextual(body.Contextual)
		if err := ev.validQuery(*body.TupleKey); err != nil {
			fail(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		ok(w, map[string]any{"allowed": ev.check(body.TupleKey.Object, body.TupleKey.Relation, body.TupleKey.User, 0)})
	case "batch-check":
		res := map[string]any{}
		for _, c := range body.Checks {
			ev.extra = contextual(c.Contextual)
			if err := ev.validQuery(c.TupleKey); err != nil {
				res[c.CorrelationID] = map[string]any{"error": map[string]string{"message": err.Error()}}
				continue
			}
			res[c.CorrelationID] = map[string]any{"allowed": ev.check(c.TupleKey.Object, c.TupleKey.Relation, c.TupleKey.User, 0)}
		}
		ok(w, map[string]any{"result": res})
	case "list-objects":
		ev.extra = contextual(body.Contextual)
		seen := map[string]bool{}
		var objs []string
		for _, k := range ev.all() {
			if strings.HasPrefix(k.Object, body.Type+":") && !seen[k.Object] {
				seen[k.Object] = true
				if ev.check(k.Object, body.Relation, body.User, 0) {
					objs = append(objs, k.Object)
				}
			}
		}
		sort.Strings(objs)
		ok(w, map[string]any{"objects": objs})
	case "list-users":
		ev.extra = contextual(body.Contextual)
		if body.Object == nil || len(body.UserFilters) != 1 {
			fail(w, http.StatusBadRequest, "validation_error", "object and one user filter are required")
			return
		}
		object, want := body.Object.Type+":"+body.Object.ID, body.UserFilters[0].Type
		seen := map[string]bool{}
		var users []map[string]any
		for _, k := range ev.all() {
			for _, cand := range []string{k.User, k.Object} {
				cand, _, _ = strings.Cut(cand, "#")
				typ, id, _ := strings.Cut(cand, ":")
				if typ != want || seen[cand] {
					continue
				}
				seen[cand] = true
				if !ev.check(object, body.Relation, cand, 0) {
					continue
				}
				if id == "*" {
					users = append(users, map[string]any{"wildcard": map[string]string{"type": typ}})
				} else {
					users = append(users, map[string]any{"object": map[string]string{"type": typ, "id": id}})
				}
			}
		}
		sort.Slice(users, func(i, j int) bool { return fmt.Sprint(users[i]) < fmt.Sprint(users[j]) })
		ok(w, map[string]any{"users": users})
	default:
		fail(w, http.StatusNotFound, "not_found", "no route")
	}
}

func contextual(c *struct {
	TupleKeys []fga.TupleKey `json:"tuple_keys"`
}) []fga.TupleKey {
	if c == nil {
		return nil
	}
	return c.TupleKeys
}

type evaluator struct {
	m      fga.Model
	tuples map[fga.TupleKey]bool
	extra  []fga.TupleKey
}

func (e *evaluator) all() []fga.TupleKey {
	out := append([]fga.TupleKey(nil), e.extra...)
	for k := range e.tuples {
		out = append(out, k)
	}
	return out
}

func typeOf(s string) string { t, _, _ := strings.Cut(s, ":"); return t }

func (e *evaluator) typeDef(t string) (fga.TypeDef, bool) {
	for _, d := range e.m.TypeDefinitions {
		if d.Type == t {
			return d, true
		}
	}
	return fga.TypeDef{}, false
}

func (e *evaluator) validQuery(k fga.TupleKey) error {
	td, ok := e.typeDef(typeOf(k.Object))
	if !ok {
		return fmt.Errorf("type '%s' not found", typeOf(k.Object))
	}
	if _, ok := td.Relations[k.Relation]; !ok {
		return fmt.Errorf("relation '%s#%s' not found", td.Type, k.Relation)
	}
	return nil
}

func (e *evaluator) valid(k fga.TupleKey) error {
	if err := e.validQuery(k); err != nil {
		return err
	}
	td, _ := e.typeDef(typeOf(k.Object))
	ut, urel, _ := strings.Cut(k.User, "#")
	wild := strings.HasSuffix(ut, ":*")
	for _, d := range td.Metadata.Relations[k.Relation].DirectlyRelatedUserTypes {
		if d.Type == typeOf(ut) && d.Relation == urel && (d.Wildcard != nil) == wild {
			return nil
		}
	}
	return fmt.Errorf("type '%s' is not an allowed type restriction for '%s#%s'", typeOf(ut), td.Type, k.Relation)
}

func (e *evaluator) check(object, relation, user string, depth int) bool {
	if depth > 25 {
		return false
	}
	td, ok := e.typeDef(typeOf(object))
	if !ok {
		return false
	}
	us, ok := td.Relations[relation]
	if !ok {
		return false
	}
	return e.eval(object, relation, us, user, depth)
}

func (e *evaluator) eval(object, relation string, us fga.Userset, user string, depth int) bool {
	switch {
	case us.This != nil:
		for _, k := range e.all() {
			if k.Object != object || k.Relation != relation {
				continue
			}
			if k.User == user || k.User == typeOf(user)+":*" {
				return true
			}
			if obj, rel, ok := strings.Cut(k.User, "#"); ok && e.check(obj, rel, user, depth+1) {
				return true
			}
		}
	case us.ComputedUserset != nil:
		return e.check(object, us.ComputedUserset.Relation, user, depth+1)
	case us.TupleToUserset != nil:
		for _, k := range e.all() {
			if k.Object == object && k.Relation == us.TupleToUserset.Tupleset.Relation &&
				e.check(k.User, us.TupleToUserset.ComputedUserset.Relation, user, depth+1) {
				return true
			}
		}
	case us.Union != nil:
		for _, c := range us.Union.Child {
			if e.eval(object, relation, c, user, depth) {
				return true
			}
		}
	case us.Intersection != nil:
		for _, c := range us.Intersection.Child {
			if !e.eval(object, relation, c, user, depth) {
				return false
			}
		}
		return true
	case us.Difference != nil:
		return e.eval(object, relation, us.Difference.Base, user, depth) &&
			!e.eval(object, relation, us.Difference.Subtract, user, depth)
	}
	return false
}
