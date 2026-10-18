package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/access"
	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/fga/fgatest"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/lifecycle"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

const notesModel = `model
  schema 1.1

type user

type folder
  relations
    define tenant: [tenant]
    define owner: [user]
    define viewer: [user, role#assignee] or owner or member from tenant

type document
  relations
    define parent: [folder]
    define editor: [user, role#assignee]
    define viewer: [user] or editor or viewer from parent
`

// setupAccess is setupFull with fine-grained permissions on, backed by OpenFGA at fgaURL.
func setupAccess(t *testing.T, fgaURL string) (*httptest.Server, *store.Store, *access.Syncer) {
	pool := testdb.New(t)
	keys, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	var logs io.Writer = io.Discard
	if os.Getenv("MATURA_TEST_LOG") != "" {
		logs = os.Stderr
	}
	log := slog.New(slog.NewTextHandler(logs, nil))
	server := api.New(st, api.DevAuthenticator{}, keys, log)
	svc := &access.Service{Client: &fga.Client{URL: fgaURL}, Store: st, StoreName: "matura-" + ids.New().String()[:8],
		Log: log}
	server.SetAccess(svc)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	return srv, st, &access.Syncer{Service: svc}
}

// TestFineGrainedPermissions runs against the fake OpenFGA; TestFineGrainedPermissionsOpenFGA against a real one.
func TestFineGrainedPermissions(t *testing.T) {
	fake := fgatest.New(t)
	runPermissions(t, fake.URL, fake)
}

func TestFineGrainedPermissionsOpenFGA(t *testing.T) {
	u := os.Getenv("MATURA_TEST_OPENFGA_URL")
	if u == "" {
		t.Skip("MATURA_TEST_OPENFGA_URL not set")
	}
	runPermissions(t, u, nil)
}

func runPermissions(t *testing.T, fgaURL string, fake *fgatest.Server) {
	srv, st, syncer := setupAccess(t, fgaURL)
	ctx := context.Background()
	round := func() {
		t.Helper()
		if err := syncer.Round(ctx); err != nil {
			t.Fatalf("sync round: %v", err)
		}
	}
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	alice := client{t: t, srv: srv, user: ids.New()}
	bob := client{t: t, srv: srv, user: ids.New()}
	carol := client{t: t, srv: srv, user: ids.New()}
	for _, c := range []client{alice, bob, carol} {
		c.must(http.StatusOK, "GET", "/v1/me", nil)
	}
	m := map[string]any{
		"slug": "notes", "name": "Notes",
		"auth":          map[string]any{"redirect_uris": []string{"http://localhost:9000/cb"}, "public_client": true},
		"roles":         []map[string]any{{"name": "writer", "permissions": []string{"note.write"}}, {"name": "reader", "permissions": []string{"note.read"}}},
		"default_role":  "reader",
		"authorization": map[string]any{"model": notesModel},
	}
	// a model that does not hold together is refused when the manifest is applied
	bad := map[string]any{}
	for k, v := range m {
		bad[k] = v
	}
	bad["authorization"] = map[string]any{"model": strings.Replace(notesModel, "or owner", "or nobody", 1)}
	op.must(http.StatusUnprocessableEntity, "PUT", "/admin/v1/apps/notes", bad)
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", m)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/secrets", map[string]any{"label": "t"})
	app := appClient{t: t, srv: srv, clientID: "notes", pass: sec["secret"].(string)}

	ta := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	tb := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "beta", "name": "Beta"})["id"].(string)
	tc := bob.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "gamma", "name": "Gamma"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+ta+"/apps/notes", nil)
	bob.must(http.StatusOK, "PUT", "/v1/tenants/"+tb+"/apps/notes", nil)
	alice.must(http.StatusCreated, "POST", "/v1/tenants/"+ta+"/members", map[string]any{"user_id": carol.user, "tenant_role": "member"})
	round()
	tidA := uuid.MustParse(ta)
	if fake != nil && !fake.Has(fga.UserSubject(tidA, carol.user), "member", fga.TenantObject(tidA)) {
		t.Fatalf("carol's membership is not mirrored: %v", fake.Tuples())
	}

	base := "/v1/apps/notes/tenants/"
	rel := func(tid string, want int, writes, deletes [][3]string) map[string]any {
		t.Helper()
		body := map[string]any{"writes": tuples(writes), "deletes": tuples(deletes)}
		code, out := app.do("POST", base+tid+"/relations", mustJSON(body))
		if code != want {
			t.Fatalf("relations in %s: %d, want %d (%v)", tid, code, want, out)
		}
		return out
	}
	check := func(tid string, user uuid.UUID, relation, object string, want bool) {
		t.Helper()
		code, out := app.do("POST", base+tid+":check", mustJSON(map[string]any{"user": "user:" + user.String(),
			"relation": relation, "object": object, "consistency": "higher"}))
		if code != http.StatusOK || out["allowed"] != want {
			t.Fatalf("check %s %s %s in %s: %d %v, want %v", user, relation, object, tid, code, out, want)
		}
	}

	rel(ta, http.StatusOK, [][3]string{{"tenant:" + ta, "tenant", "folder:f1"}, {"folder:f1", "parent", "document:d1"},
		{"role:writer#assignee", "editor", "document:d2"}}, nil)
	rel(ta, http.StatusOK, [][3]string{{"tenant:" + ta, "tenant", "folder:f1"}}, nil) // repeat: no error
	rel(tb, http.StatusOK, [][3]string{{"tenant:" + tb, "tenant", "folder:f9"}, {"folder:f9", "parent", "document:d9"}}, nil)

	check(ta, carol.user, "viewer", "document:d1", true) // member of Acme, through folder and tenant
	check(ta, alice.user, "viewer", "document:d1", true) // owner implies member
	check(tb, bob.user, "viewer", "document:d1", false)  // Beta has no d1, and bob is not in Acme
	check(ta, bob.user, "viewer", "document:d1", false)
	check(tb, bob.user, "viewer", "document:d9", true)
	check(ta, carol.user, "editor", "document:d2", false)

	// an app role grant becomes role:<name>#assignee; revoking it takes it away
	g := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+ta+"/grants", map[string]any{"app": "notes",
		"user_id": carol.user, "role": "writer"})
	round()
	check(ta, carol.user, "editor", "document:d2", true)
	check(ta, carol.user, "viewer", "document:d2", true)
	// renaming the role moves the grant's tuple
	op.must(http.StatusOK, "PATCH", "/admin/v1/apps/notes/roles/writer", map[string]any{"name": "author"})
	round()
	check(ta, carol.user, "editor", "document:d2", false)
	rel(ta, http.StatusOK, [][3]string{{"role:author#assignee", "editor", "document:d2"}}, nil)
	check(ta, carol.user, "editor", "document:d2", true)
	alice.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+ta+"/grants/"+g["id"].(string), nil)
	round()
	check(ta, carol.user, "editor", "document:d2", false)

	// batch check answers in order; a malformed entry gets its own error
	code, out := app.do("POST", base+ta+":batch-check", mustJSON(map[string]any{"checks": []map[string]any{
		{"user": "user:" + carol.user.String(), "relation": "viewer", "object": "document:d1"},
		{"user": "user:" + bob.user.String(), "relation": "viewer", "object": "document:d1"},
		{"user": "user:" + bob.user.String(), "relation": "viewer", "object": "invoice:i1"},
	}}))
	res, _ := out["results"].([]any)
	if code != http.StatusOK || len(res) != 3 || res[0].(map[string]any)["allowed"] != true ||
		res[1].(map[string]any)["allowed"] != false || res[2].(map[string]any)["error"] == nil {
		t.Fatalf("batch-check: %d %v", code, out)
	}
	// list objects shows only this tenant's objects, by the names the app used
	code, out = app.do("POST", base+ta+":list-objects", mustJSON(map[string]any{"user": "user:" + alice.user.String(),
		"relation": "viewer", "type": "document", "consistency": "higher"}))
	if objs, _ := out["objects"].([]any); code != http.StatusOK || len(objs) != 1 || objs[0] != "document:d1" {
		t.Fatalf("list-objects: %d %v", code, out)
	}

	// isolation and validation
	rel(tc, http.StatusNotFound, [][3]string{{"user:" + bob.user.String(), "owner", "folder:x"}}, nil) // not enabled
	rel(ids.New().String(), http.StatusNotFound, [][3]string{{"user:" + bob.user.String(), "owner", "folder:x"}}, nil)
	rel(ta, http.StatusUnprocessableEntity, [][3]string{{"user:" + bob.user.String(), "member", "tenant:" + ta}}, nil)
	rel(ta, http.StatusUnprocessableEntity, [][3]string{{"user:" + bob.user.String(), "owner", "invoice:x"}}, nil)
	rel(ta, http.StatusUnprocessableEntity, nil, nil)
	if code, out := app.do("POST", "/v1/apps/other/tenants/"+ta+":check", "{}"); code != http.StatusNotFound {
		t.Fatalf("another app's path: %d %v", code, out)
	}
	if code, out := app.do("POST", base+ta+":nope", "{}"); code != http.StatusNotFound {
		t.Fatalf("unknown action: %d %v", code, out)
	}
	// relation OpenFGA does not know: refused as invalid
	rel(ta, http.StatusUnprocessableEntity, [][3]string{{"user:" + bob.user.String(), "nope", "folder:f1"}}, nil)

	// removing carol from Acme takes her tenant-derived access away
	alice.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+ta+"/members/"+carol.user.String(), nil)
	round()
	check(ta, carol.user, "viewer", "document:d1", false)
	rel(ta, http.StatusOK, nil, [][3]string{{"folder:f1", "parent", "document:d1"}})
	check(ta, alice.user, "viewer", "document:d1", false)

	// a deleted tenant's tuples go, its neighbours' stay
	op.must(http.StatusAccepted, "DELETE", "/admin/v1/tenants/"+tb+"?grace_days=0", nil)
	if _, _, err := (&lifecycle.Purger{Store: st}).Round(ctx); err != nil {
		t.Fatal(err)
	}
	round()
	if fake != nil {
		for _, tu := range fake.Tuples() {
			if strings.Contains(tu, tb) {
				t.Fatalf("tuple of the deleted tenant left: %s", tu)
			}
		}
		if !fake.Has(fga.UserSubject(tidA, alice.user), "owner", fga.TenantObject(tidA)) {
			t.Fatal("Acme's tuples were removed too")
		}
	}

	if fake == nil {
		return
	}
	// OpenFGA lost its data: the next call fails once, then the store is set up again and every fact written back
	fake.Wipe()
	if code, out := app.do("POST", base+ta+":check", mustJSON(map[string]any{"user": "user:" + alice.user.String(),
		"relation": "viewer", "object": "folder:f1"})); code != http.StatusServiceUnavailable {
		t.Fatalf("check after wipe: %d %v", code, out)
	}
	round()
	if !fake.Has(fga.UserSubject(tidA, alice.user), "owner", fga.TenantObject(tidA)) {
		t.Fatalf("facts not written again: %v", fake.Tuples())
	}
	rel(ta, http.StatusOK, [][3]string{{"tenant:" + ta, "tenant", "folder:f1"}}, nil)
	check(ta, alice.user, "viewer", "folder:f1", true)

	// OpenFGA down: 503, retry later
	fake.SetDown(true)
	if code, _ := app.do("POST", base+ta+":check", mustJSON(map[string]any{"user": "user:" + alice.user.String(),
		"relation": "viewer", "object": "folder:f1"})); code != http.StatusServiceUnavailable {
		t.Fatalf("check while down: %d", code)
	}
	fake.SetDown(false)
}

// TestPermissionsWithoutOpenFGA: without MATURA_OPENFGA_URL the endpoints answer 501, and an app without a model
// gets 409 when OpenFGA is there.
func TestPermissionsWithoutOpenFGA(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/secrets", map[string]any{"label": "t"})
	app := appClient{t: t, srv: srv, clientID: "devflow", pass: sec["secret"].(string)}
	for _, p := range []string{"/relations", ":check", ":batch-check", ":list-objects"} {
		if code, out := app.do("POST", "/v1/apps/devflow/tenants/"+ids.New().String()+p, "{}"); code != http.StatusNotImplemented ||
			!strings.HasSuffix(out["type"].(string), "/permissions-not-configured") {
			t.Fatalf("%s: %d %v", p, code, out)
		}
	}

	fake := fgatest.New(t)
	srv2, _, _ := setupAccess(t, fake.URL)
	op2 := client{t: t, srv: srv2, user: ids.New(), op: true}
	alice := client{t: t, srv: srv2, user: ids.New()}
	op2.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	sec = op2.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/secrets", map[string]any{"label": "t"})
	app = appClient{t: t, srv: srv2, clientID: "devflow", pass: sec["secret"].(string)}
	tid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/devflow", nil)
	if code, out := app.do("POST", "/v1/apps/devflow/tenants/"+tid+":check", "{}"); code != http.StatusConflict ||
		!strings.HasSuffix(out["type"].(string), "/no-authorization-model") {
		t.Fatalf("no model: %d %v", code, out)
	}
}

func tuples(in [][3]string) []map[string]string {
	out := []map[string]string{}
	for _, t := range in {
		out = append(out, map[string]string{"user": t[0], "relation": t[1], "object": t[2]})
	}
	return out
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
