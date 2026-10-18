package fga_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/fga/fgatest"
)

// sampleDSL is a model as an app writes it; it also runs as is in the OpenFGA playground.
const sampleDSL = `model
  schema 1.1

type user

type tenant # Matura's: only relations Matura defines
  relations
    define admin: [user] or owner
    define owner: [user]
    define billing: [user]
    define member: [user] or admin or billing

type folder
  relations
    define tenant: [tenant]
    define owner: [user]
    define viewer: [user, user:*, role#assignee] or owner or member from tenant

type document
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, group#member, role#assignee] or owner
    define viewer: [user] or editor or viewer from parent
    define blocked: [user]
    define can_read: viewer but not blocked
    define can_share: (owner or editor) and viewer
`

func TestParseDSL(t *testing.T) {
	own, err := fga.ParseModel(json.RawMessage(mustJSON(sampleDSL)))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(own.TypeNames(), ","); got != "folder,document" {
		t.Fatalf("own types: %s", got)
	}
	doc := own.TypeDefinitions[1]
	v := doc.Relations["viewer"]
	if v.Union == nil || len(v.Union.Child) != 3 || v.Union.Child[0].This == nil ||
		v.Union.Child[1].ComputedUserset.Relation != "editor" ||
		v.Union.Child[2].TupleToUserset.Tupleset.Relation != "parent" ||
		v.Union.Child[2].TupleToUserset.ComputedUserset.Relation != "viewer" {
		t.Fatalf("viewer: %s", mustJSON(v))
	}
	if d := doc.Relations["can_read"].Difference; d == nil || d.Subtract.ComputedUserset.Relation != "blocked" {
		t.Fatalf("can_read: %s", mustJSON(doc.Relations["can_read"]))
	}
	if i := doc.Relations["can_share"].Intersection; i == nil || i.Child[0].Union == nil {
		t.Fatalf("can_share: %s", mustJSON(doc.Relations["can_share"]))
	}
	refs := own.TypeDefinitions[0].Metadata.Relations["viewer"].DirectlyRelatedUserTypes
	if len(refs) != 3 || refs[1].Wildcard == nil || refs[2].Type != "role" || refs[2].Relation != "assignee" {
		t.Fatalf("folder viewer types: %s", mustJSON(refs))
	}

	// the JSON form reads the same
	again, err := fga.ParseModel(json.RawMessage(mustJSON(own)))
	if err != nil || again.Hash() != own.Hash() {
		t.Fatalf("JSON form: %v", err)
	}
}

func TestParseModelErrors(t *testing.T) {
	head := "model\n  schema 1.1\ntype user\n"
	for name, src := range map[string]string{
		"mixed operators":  head + "type doc\n  relations\n    define a: [user]\n    define b: [user]\n    define c: a or b and a\n",
		"unknown relation": head + "type doc\n  relations\n    define a: [user] or nope\n",
		"unknown type":     head + "type doc\n  relations\n    define a: [person]\n",
		"bad userset":      head + "type doc\n  relations\n    define a: [tenant#nope]\n",
		"condition":        head + "type doc\n  relations\n    define a: [user with fresh]\n",
		"matura type":      head + "type tenant\n  relations\n    define auditor: [user]\ntype doc\n  relations\n    define a: [user]\n",
		"no own types":     head,
		"type name":        head + "type Doc\n  relations\n    define a: [user]\n",
		"bad from":         head + "type doc\n  relations\n    define p: [user]\n    define a: viewer from p\n",
		"schema":           "model\n  schema 1.0\ntype doc\n",
		"module":           "module x\n",
		"twice":            head + "type doc\n  relations\n    define a: [user]\n    define a: [user]\n",
	} {
		if _, err := fga.ParseModel(json.RawMessage(mustJSON(src))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := fga.ParseModel(json.RawMessage(`{"schema_version":"1.1","type_definitions":[],"conditions":{"c":{}}}`)); err == nil {
		t.Error("conditions accepted")
	}
}

func TestForApp(t *testing.T) {
	own, err := fga.ParseModel(json.RawMessage(mustJSON(sampleDSL)))
	if err != nil {
		t.Fatal(err)
	}
	m := fga.ForApp("notes", own)
	var doc fga.TypeDef
	types := map[string]bool{}
	for _, td := range m.TypeDefinitions {
		types[td.Type] = true
		if td.Type == "notes.document" {
			doc = td
		}
	}
	for _, want := range []string{"user", "group", "tenant", "workspace", "role", "notes.folder", "notes.document"} {
		if !types[want] {
			t.Errorf("missing type %s", want)
		}
	}
	if got := doc.Metadata.Relations["parent"].DirectlyRelatedUserTypes[0].Type; got != "notes.folder" {
		t.Fatalf("parent refers to %s", got)
	}
	if got := doc.Metadata.Relations["editor"].DirectlyRelatedUserTypes[1].Type; got != "group" {
		t.Fatalf("Matura types keep their name: %s", got)
	}
	if own.TypeDefinitions[1].Type != "document" {
		t.Fatal("ForApp changed the app's model")
	}
}

func TestNamespace(t *testing.T) {
	ta, tb := uuid.New(), uuid.New()
	a := fga.Namespace{App: "notes", Tenant: ta, Types: []string{"document", "folder"}}
	b := fga.Namespace{App: "notes", Tenant: tb, Types: []string{"document", "folder"}}
	other := fga.Namespace{App: "crm", Tenant: ta, Types: []string{"document"}}

	k, err := a.Key("user:u1", "viewer", "document:d1", true)
	if err != nil {
		t.Fatal(err)
	}
	if k.Object != "notes.document:"+ta.String()+"/d1" || k.User != "user:"+ta.String()+"/u1" {
		t.Fatalf("key: %+v", k)
	}
	kb, _ := b.Key("user:u1", "viewer", "document:d1", true)
	ko, _ := other.Key("user:u1", "viewer", "document:d1", true)
	if kb.Object == k.Object || ko.Object == k.Object {
		t.Fatal("tenants or apps share an object")
	}
	if u, _ := a.User("role:editor#assignee"); u != "role:"+ta.String()+"/notes/editor#assignee" {
		t.Fatalf("role: %s", u)
	}
	w := uuid.New()
	if u, _ := a.User("role:editor@" + w.String() + "#assignee"); u != fga.RoleObject(ta, "notes", "editor", &w)+"#assignee" {
		t.Fatalf("workspace role: %s", u)
	}
	if u, _ := a.User("user:*"); u != "user:*" {
		t.Fatalf("wildcard: %s", u)
	}
	for _, bad := range [][3]string{
		{"user:u1", "viewer", "tenant:" + ta.String()}, // Matura's
		{"user:u1", "viewer", "role:editor"},
		{"user:u1", "viewer", "invoice:i1"}, // not the app's
		{"user:u1", "Viewer", "document:d1"},
		{"user u1", "viewer", "document:d1"},
		{"user:u1", "viewer", "document:*"},
		{"user:u1", "viewer", "document"},
		{"user:u1#BAD", "viewer", "document:d1"},
	} {
		if _, err := a.Key(bad[0], bad[1], bad[2], true); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if _, err := a.Key("user:u1", "member", "tenant:"+ta.String(), false); err != nil {
		t.Errorf("checks may name Matura's types: %v", err)
	}
	if got, ok := a.FromObject(k.Object); !ok || got != "document:d1" {
		t.Fatalf("from object: %s %v", got, ok)
	}
	for _, o := range []string{kb.Object, ko.Object, "notes.document:d1", "role:" + ta.String() + "/crm/x"} {
		if _, ok := a.FromObject(o); ok {
			t.Errorf("%s shown to notes in tenant A", o)
		}
	}
	if !fga.InTenant(k.Object, ta) || fga.InTenant(k.Object, tb) {
		t.Fatal("InTenant")
	}
}

// TestClientAgainstFake drives the client against the fake: writes repeat safely and checks follow the model.
func TestClientAgainstFake(t *testing.T) {
	runClient(t, fgatest.New(t).URL)
}

// TestClientAgainstOpenFGA runs the same against a real OpenFGA (MATURA_TEST_OPENFGA_URL, e.g. `openfga run` with
// the memory datastore), which also proves the parser's JSON is what OpenFGA accepts.
func TestClientAgainstOpenFGA(t *testing.T) {
	u := os.Getenv("MATURA_TEST_OPENFGA_URL")
	if u == "" {
		t.Skip("MATURA_TEST_OPENFGA_URL not set")
	}
	runClient(t, u)
}

func runClient(t *testing.T, url string) {
	ctx := context.Background()
	c := &fga.Client{URL: url}
	name := "test-" + uuid.NewString()[:8]
	if id, err := c.FindStore(ctx, name); err != nil || id != "" {
		t.Fatalf("find before create: %q %v", id, err)
	}
	store, err := c.CreateStore(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := c.FindStore(ctx, name); err != nil || id != store {
		t.Fatalf("find: %q %v", id, err)
	}
	if ok, err := c.StoreExists(ctx, store); !ok || err != nil {
		t.Fatalf("exists: %v %v", ok, err)
	}
	base, err := c.WriteModel(ctx, store, fga.Base())
	if err != nil {
		t.Fatal(err)
	}
	own, err := fga.ParseModel(json.RawMessage(mustJSON(sampleDSL)))
	if err != nil {
		t.Fatal(err)
	}
	model, err := c.WriteModel(ctx, store, fga.ForApp("notes", own))
	if err != nil {
		t.Fatal(err)
	}
	ta, tb := uuid.New(), uuid.New()
	ana, bo, cy := uuid.New(), uuid.New(), uuid.New()
	// Matura's facts, written with the base model: ana is a member of A, bo an admin of B, cy an admin of A
	facts := []fga.TupleKey{
		{User: fga.UserSubject(ta, ana), Relation: "member", Object: fga.TenantObject(ta)},
		{User: fga.UserSubject(tb, bo), Relation: "admin", Object: fga.TenantObject(tb)},
		{User: fga.UserSubject(ta, cy), Relation: "admin", Object: fga.TenantObject(ta)},
		{User: fga.UserSubject(ta, bo), Relation: "assignee", Object: fga.RoleObject(ta, "notes", "editor", nil)},
	}
	for i := 0; i < 2; i++ { // the second write repeats every tuple: no error
		if err := c.Write(ctx, store, base, facts, nil); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	na := fga.Namespace{App: "notes", Tenant: ta, Types: own.TypeNames()}
	nb := fga.Namespace{App: "notes", Tenant: tb, Types: own.TypeNames()}
	var writes []fga.TupleKey
	for _, w := range [][3]string{
		{"tenant:" + ta.String(), "tenant", "folder:f1"},
		{"folder:f1", "parent", "document:d1"},
		{"role:editor#assignee", "editor", "document:d2"},
		{"user:" + cy.String(), "blocked", "document:d1"},
	} {
		k, err := na.Key(w[0], w[1], w[2], true)
		if err != nil {
			t.Fatal(err)
		}
		writes = append(writes, k)
	}
	if err := c.Write(ctx, store, model, writes, nil); err != nil {
		t.Fatal(err)
	}
	check := func(ns fga.Namespace, user, rel, obj string, want bool) {
		t.Helper()
		k, err := ns.Key(user, rel, obj, false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Check(ctx, store, fga.Query{Model: model, Higher: true}, k)
		if err != nil || got != want {
			t.Fatalf("%s %s %s in %s: %v (%v), want %v", user, rel, obj, ns.Tenant, got, err, want)
		}
	}
	check(na, "user:"+ana.String(), "viewer", "document:d1", true)     // member of A, via folder and tenant
	check(na, "user:"+cy.String(), "viewer", "document:d1", true)      // admin implies member
	check(na, "user:"+cy.String(), "can_read", "document:d1", false)   // but blocked
	check(na, "user:"+ana.String(), "can_read", "document:d1", true)   //
	check(na, "user:"+bo.String(), "editor", "document:d2", true)      // role grant in A
	check(nb, "user:"+bo.String(), "viewer", "document:d1", false)     // B's admin, same document name: B has none
	check(nb, "user:"+bo.String(), "editor", "document:d2", false)     // the grant was in A
	check(na, "user:"+ana.String(), "can_share", "document:d2", false) //

	keys := []fga.TupleKey{}
	for _, u := range []uuid.UUID{ana, bo} {
		k, _ := na.Key("user:"+u.String(), "viewer", "document:d1", false)
		keys = append(keys, k)
	}
	k, _ := na.Key("user:"+ana.String(), "editor", "document:d2", false)
	keys = append(keys, k)
	res, err := c.BatchCheck(ctx, store, fga.Query{Model: model}, keys)
	if err != nil || len(res) != 3 || !res[0].Allowed || res[1].Allowed || res[2].Allowed {
		t.Fatalf("batch: %+v %v", res, err)
	}
	// a contextual tuple counts for this check only
	ctxKey, _ := na.Key("user:"+ana.String(), "owner", "document:d2", false)
	if ok, err := c.Check(ctx, store, fga.Query{Model: model, Contextual: []fga.TupleKey{ctxKey}}, ctxKey); !ok || err != nil {
		t.Fatalf("contextual: %v %v", ok, err)
	}

	user, _ := na.User("user:" + ana.String())
	typ, _ := na.Type("document")
	objs, err := c.ListObjects(ctx, store, fga.Query{Model: model, Higher: true}, user, "viewer", typ)
	if err != nil || len(objs) != 1 {
		t.Fatalf("list: %v %v", objs, err)
	}
	if o, ok := na.FromObject(objs[0]); !ok || o != "document:d1" {
		t.Fatalf("list maps to %s", o)
	}

	// a tuple on a relation the model lacks is refused as invalid
	bad, _ := na.Key("user:"+ana.String(), "nope", "document:d1", true)
	var fe *fga.Error
	if err := c.Write(ctx, store, model, []fga.TupleKey{bad}, nil); !asErr(err, &fe) || !fe.Invalid() {
		t.Fatalf("bad write: %v", err)
	}
	// deleting what is missing is not an error; deleting with the base model works for app types
	if err := c.Write(ctx, store, base, nil, append(writes, bad)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	page, _, err := c.Read(ctx, store, nil, "")
	if err != nil || len(page) != len(facts) {
		t.Fatalf("read after delete: %d %v", len(page), err)
	}
	if _, err := c.Check(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAV", fga.Query{}, keys[0]); !asErr(err, &fe) || !fe.Stale() {
		t.Fatalf("unknown store: %v", err)
	}
}

func asErr(err error, target **fga.Error) bool {
	e, ok := err.(*fga.Error)
	if ok {
		*target = e
	}
	return ok
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
