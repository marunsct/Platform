package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/placement"
)

func (c appClient) do(method, path string, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, strings.NewReader(body))
	req.SetBasicAuth(c.clientID, c.pass)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// connectAs opens a connection with placement credentials.
func connectAs(t *testing.T, c map[string]any) (*pgx.Conn, error) {
	t.Helper()
	u := url.URL{Scheme: "postgres", User: url.UserPassword(c["user"].(string), c["password"].(string)),
		Host: fmt.Sprintf("%s:%v", c["host"], c["port"]), Path: "/" + c["database"].(string),
		RawQuery: "sslmode=disable&connect_timeout=5"}
	return pgx.Connect(context.Background(), u.String())
}

// TestPlatformManagedPlacements: the provisioner creates shared, schema and database storage on a registered server;
// one tenant's role cannot reach another tenant's schema or database; deleting a tenant drops its storage once the
// app confirms its data is gone.
func TestPlatformManagedPlacements(t *testing.T) {
	srv, st, keys := setupFull(t)
	ctx := context.Background()
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	alice := client{t: t, srv: srv, user: ids.New()}
	alice.must(http.StatusOK, "GET", "/v1/me", nil) // record the user
	sfx := strings.ReplaceAll(ids.New().String()[24:], "-", "")[:8]
	slug := "pl" + sfx

	u, _ := url.Parse(os.Getenv("MATURA_TEST_DATABASE_URL"))
	port, _ := strconv.Atoi(u.Port())
	op.must(http.StatusCreated, "POST", "/admin/v1/db-servers", map[string]any{
		"name": "pg-" + sfx, "host": u.Hostname(), "port": port, "admin_user": u.User.Username(),
		"admin_password": "unused-in-trust-auth", "sslmode": "disable"})
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/"+slug, map[string]any{
		"slug": slug, "name": "Placement test",
		"auth":  map[string]any{"redirect_uris": []string{"http://localhost:9000/cb"}, "public_client": true},
		"roles": []map[string]any{{"name": "user", "permissions": []string{"thing.read"}}}, "default_role": "user",
		"tenancy": map[string]any{"modes": []string{"shared", "schema", "database"}, "managers": []string{"platform"}},
	})
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/"+slug+"/secrets", map[string]any{"label": "test"})
	app := appClient{t: t, srv: srv, clientID: slug, pass: sec["secret"].(string)}
	for _, m := range []string{"schema", "database"} {
		op.must(http.StatusOK, "PUT", "/admin/v1/plans/"+m+"-"+sfx, map[string]any{"name": m, "data_mode_required": m})
	}

	tenants := map[string]string{} // name -> id
	for _, tc := range []struct{ name, plan string }{
		{"sa", "schema"}, {"sb", "schema"}, {"da", "database"}, {"db", "database"}, {"sh", ""},
	} {
		body := map[string]any{"slug": tc.name + "-" + sfx, "name": tc.name, "owner_id": alice.user}
		if tc.plan != "" {
			body["plan"] = tc.plan + "-" + sfx
		}
		tid := op.must(http.StatusCreated, "POST", "/v1/tenants", body)["id"].(string)
		tenants[tc.name] = tid
		en := alice.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/"+slug, nil)
		if want := map[bool]string{true: tc.plan, false: "shared"}[tc.plan != ""]; en["placement"].(map[string]any)["mode"] != want {
			t.Fatalf("%s placement: %v", tc.name, en["placement"])
		}
	}
	// before provisioning there is nothing to connect to
	if code, _ := app.do("POST", "/v1/apps/"+slug+"/placements/"+tenants["sa"]+"/credentials", ""); code != http.StatusConflict {
		t.Fatalf("credentials before provisioning: %d", code)
	}

	prov := &placement.Provisioner{Store: st, Keys: keys}
	if n, err := prov.Round(ctx); err != nil || n != 5 {
		t.Fatalf("round: %d, %v", n, err)
	}
	creds := map[string]map[string]any{}
	for name, tid := range tenants {
		code, p := app.do("GET", "/v1/apps/"+slug+"/placements/"+tid, "")
		if code != http.StatusOK || p["state"] != "provisioned" {
			t.Fatalf("%s: %d %v", name, code, p)
		}
		code, c := app.do("POST", "/v1/apps/"+slug+"/placements/"+tid+"/credentials", "")
		if code != http.StatusOK || c["password"] == "" {
			t.Fatalf("%s credentials: %d %v", name, code, c)
		}
		creds[name] = c
	}
	if creds["sa"]["database"] != creds["sb"]["database"] || creds["sa"]["search_path"] == creds["sb"]["search_path"] {
		t.Fatalf("schema mode: %v / %v", creds["sa"], creds["sb"])
	}
	if creds["da"]["database"] == creds["db"]["database"] {
		t.Fatalf("database mode shares a database: %v", creds["da"]["database"])
	}

	// schema mode: A creates a table in its schema; B's role cannot read A's schema
	ca, err := connectAs(t, creds["sa"])
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close(ctx)
	if _, err := ca.Exec(ctx, `CREATE TABLE notes (id int PRIMARY KEY); INSERT INTO notes VALUES (1)`); err != nil {
		t.Fatalf("tenant A creates in its schema: %v", err)
	}
	cb, err := connectAs(t, creds["sb"])
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close(ctx)
	if _, err := cb.Exec(ctx, fmt.Sprintf(`SELECT * FROM %s.notes`, pgx.Identifier{creds["sa"]["search_path"].(string)}.Sanitize())); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("tenant B read tenant A's schema: %v", err)
	}
	if _, err := cb.Exec(ctx, `CREATE TABLE public.leak (id int)`); err == nil {
		t.Fatal("tenant B can create tables in the bridge database's public schema")
	}

	// database mode: A's role cannot connect to B's database
	cross := map[string]any{}
	for k, v := range creds["da"] {
		cross[k] = v
	}
	cross["database"] = creds["db"]["database"]
	if c, err := connectAs(t, cross); err == nil {
		c.Close(ctx)
		t.Fatal("tenant A's role connected to tenant B's database")
	} else if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected error: %v", err)
	}

	// shared mode: the runtime role cannot create tables, the migrate role can
	_, mig := app.do("POST", "/v1/apps/"+slug+"/placements/"+tenants["sh"]+"/credentials", `{"purpose":"migrate"}`)
	if mig["user"] == creds["sh"]["user"] {
		t.Fatalf("shared mode migrates with the runtime role: %v", mig)
	}
	cm, err := connectAs(t, mig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cm.Exec(ctx, `CREATE TABLE IF NOT EXISTS items (tenant_id uuid, name text)`); err != nil {
		t.Fatalf("migrate role creates a table: %v", err)
	}
	cm.Close(ctx)
	cr, err := connectAs(t, creds["sh"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cr.Exec(ctx, `INSERT INTO items VALUES ($1, 'x')`, tenants["sh"]); err != nil {
		t.Fatalf("runtime role writes: %v", err)
	}
	if _, err := cr.Exec(ctx, `DROP TABLE items`); err == nil {
		t.Fatal("runtime role dropped a table")
	}
	cr.Close(ctx)

	// ready, then the tenant is deleted: retiring until the app confirms, then dropped
	if code, p := app.do("POST", "/v1/apps/"+slug+"/placements/"+tenants["da"]+":ready", ""); code != http.StatusOK || p["state"] != "ready" {
		t.Fatalf("ready: %d %v", code, p)
	}
	if code, _ := app.do("POST", "/v1/apps/"+slug+"/placements/"+tenants["da"]+":deleted", ""); code != http.StatusConflict {
		t.Fatalf(":deleted before the tenant is deleted: %d", code)
	}
	op.must(http.StatusAccepted, "DELETE", "/v1/tenants/"+tenants["da"], nil)
	if _, p := app.do("GET", "/v1/apps/"+slug+"/placements/"+tenants["da"], ""); p["state"] != "retiring" {
		t.Fatalf("after tenant deletion: %v", p)
	}
	if n, _ := prov.Round(ctx); n != 0 {
		t.Fatalf("dropped before the app confirmed: %d", n)
	}
	if code, _ := app.do("POST", "/v1/apps/"+slug+"/placements/"+tenants["da"]+":deleted", ""); code != http.StatusOK {
		t.Fatalf(":deleted: %d", code)
	}
	if n, err := prov.Round(ctx); err != nil || n != 1 {
		t.Fatalf("drop round: %d %v", n, err)
	}
	if _, p := app.do("GET", "/v1/apps/"+slug+"/placements/"+tenants["da"], ""); p["state"] != "deleted" {
		t.Fatalf("after drop: %v", p)
	}
	admin, err := pgx.Connect(ctx, os.Getenv("MATURA_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	var left bool
	_ = admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)
		OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $2)`, creds["da"]["database"], creds["da"]["user"]).Scan(&left)
	if left {
		t.Fatal("the deleted tenant's database or role is still there")
	}

	// the tenant's own view
	list := alice.must(http.StatusOK, "GET", "/v1/tenants/"+tenants["sa"]+"/placements", nil)["items"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["schema_name"] != creds["sa"]["search_path"] {
		t.Fatalf("tenant placements: %v", list)
	}
	t.Cleanup(func() { dropPlacementStorage(t, slug) })
}

// TestAppManagedPlacement: an app that keeps its own storage registers it, confirms it ready, and gets no
// credentials from Matura.
func TestAppManagedPlacement(t *testing.T) {
	srv := setup(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/notes", notesManifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/notes/secrets", map[string]any{"label": "b"})
	app := appClient{t: t, srv: srv, clientID: "notes", pass: sec["secret"].(string)}
	alice := client{t: t, srv: srv, user: ids.New()}
	tid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/notes", nil)

	if code, _ := app.do("PUT", "/v1/apps/notes/placements/"+tid, `{}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("register without a label: %d", code)
	}
	code, p := app.do("PUT", "/v1/apps/notes/placements/"+tid, `{"location_label":"eu-1 / notes-db"}`)
	if code != http.StatusOK || p["state"] != "provisioned" || p["location_label"] != "eu-1 / notes-db" {
		t.Fatalf("register: %d %v", code, p)
	}
	if code, _ := app.do("POST", "/v1/apps/notes/placements/"+tid+"/credentials", ""); code != http.StatusConflict {
		t.Fatalf("credentials for app-managed storage: %d", code)
	}
	if code, p := app.do("POST", "/v1/apps/notes/placements/"+tid+":ready", ""); code != http.StatusOK || p["state"] != "ready" {
		t.Fatalf("ready: %d %v", code, p)
	}
	if code, _ := app.do("POST", "/v1/apps/notes/placements/"+tid+":nonsense", ""); code != http.StatusNotFound {
		t.Fatalf("unknown action: %d", code)
	}
	// another app cannot see it
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	sec2 := op.must(http.StatusCreated, "POST", "/admin/v1/apps/devflow/secrets", map[string]any{"label": "b"})
	other := appClient{t: t, srv: srv, clientID: "devflow", pass: sec2["secret"].(string)}
	if code, _ := other.do("GET", "/v1/apps/notes/placements/"+tid, ""); code != http.StatusNotFound {
		t.Fatalf("another app reads the placement: %d", code)
	}
	if code, _ := other.do("GET", "/v1/apps/devflow/placements/"+tid, ""); code != http.StatusNotFound {
		t.Fatalf("placement of an app the tenant did not enable: %d", code)
	}
	// feed carries the lifecycle
	_, feed := app.get("/v1/apps/notes/changes")
	types := strings.Join(feedTypes(feed["items"].([]any)), " ")
	if !strings.Contains(types, "matura.placement.provisioned") || !strings.Contains(types, "matura.placement.ready") {
		t.Fatalf("feed: %s", types)
	}
}

// dropPlacementStorage removes what a test's provisioner created on the shared test server.
func dropPlacementStorage(t *testing.T, app string) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, os.Getenv("MATURA_TEST_DATABASE_URL"))
	if err != nil {
		return
	}
	defer admin.Close(ctx)
	rows, _ := admin.Query(ctx, `SELECT datname FROM pg_database WHERE datname LIKE $1`, app+`\_%`)
	dbs, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	for _, db := range dbs {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{db}.Sanitize()+" WITH (FORCE)")
	}
	rows, _ = admin.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname LIKE $1`, app+`\_%`)
	roles, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	for _, r := range roles {
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{r}.Sanitize())
	}
}
