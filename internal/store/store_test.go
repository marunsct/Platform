package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

var ctx = context.Background()

func setup(t *testing.T) (*store.Store, *pgxpool.Pool) {
	pool := testdb.New(t)
	return store.New(pool), pool
}

func user(t *testing.T, st *store.Store, email string) uuid.UUID {
	t.Helper()
	u, err := st.UpsertUser(ctx, store.UserProfile{ID: ids.New(), Email: email, EmailVerified: true, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func tenant(t *testing.T, st *store.Store, owner uuid.UUID, slug string) store.Tenant {
	t.Helper()
	tn, err := st.CreateTenant(ctx, store.Scope{UserID: owner}, store.NewTenant{Slug: slug, Name: slug}, owner)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

var devflow = store.Manifest{
	Slug: "devflow", Name: "DevFlow",
	Auth: store.ManifestAuth{RedirectURIs: []string{"http://localhost:8000/auth/callback"}, PublicClient: true},
	Roles: []store.RoleDef{
		{Name: "admin", Permissions: []string{"*"}},
		{Name: "operator", Permissions: []string{"run.read", "run.start"}},
		{Name: "viewer", Permissions: []string{"run.read"}},
	},
	DefaultRole: "viewer", OwnerRole: "admin",
	Tenancy: store.Tenancy{Modes: []string{"shared", "schema", "database"}, Managers: []string{"platform", "app"}},
}

func TestRowLevelSecurityFailsClosed(t *testing.T) {
	st, pool := setup(t)
	a := user(t, st, "a@acme.test")
	tenant(t, st, a, "acme")

	// the runtime role with no tenant set sees no tenant-owned rows at all
	for _, table := range []string{"tenant", "workspace", "membership", "tenant_app", "role_grant", "placement",
		"support_access"} {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows visible without a tenant context", table, n)
		}
	}
	// and cannot write a row for a tenant it is not in
	_, err := pool.Exec(ctx, `INSERT INTO tenant (id, slug, name, kind, status, version)
		VALUES ($1, 'sneaky', 'x', 'company', 'active', 1)`, ids.New())
	if err == nil {
		t.Fatal("insert without tenant context was allowed")
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	st, _ := setup(t)
	a := user(t, st, "a@acme.test")
	b := user(t, st, "b@globex.test")
	acme := tenant(t, st, a, "acme")
	globex := tenant(t, st, b, "globex")

	got, err := st.ListTenants(ctx, store.Scope{UserID: b})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != globex.ID {
		t.Fatalf("b sees %v, want only globex", got)
	}
	ops, err := st.ListTenants(ctx, store.Scope{Operator: true})
	if err != nil || len(ops) != 2 {
		t.Fatalf("operator sees %d tenants (%v), want 2", len(ops), err)
	}

	// acting in globex, acme's workspace cannot be reached even with its id
	acmeWS, err := st.ListWorkspaces(ctx, store.Scope{UserID: a}, acme.ID)
	if err != nil || len(acmeWS) != 1 || !acmeWS[0].IsDefault {
		t.Fatalf("acme workspaces: %v %v", acmeWS, err)
	}
	name := "stolen"
	_, err = st.UpdateWorkspace(ctx, store.Scope{UserID: b}, globex.ID, acmeWS[0].ID, store.WorkspacePatch{Name: &name})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant workspace update: %v, want not found", err)
	}
	if _, err := st.MembershipOf(ctx, acme.ID, b); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("b's membership in acme: %v, want not found", err)
	}
}

func TestSlugsAreValidatedAndUnique(t *testing.T) {
	st, _ := setup(t)
	a := user(t, st, "a@acme.test")
	tenant(t, st, a, "acme")
	_, err := st.CreateTenant(ctx, store.Scope{UserID: a}, store.NewTenant{Slug: "acme", Name: "again"}, a)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate slug: %v", err)
	}
	for _, bad := range []string{"Acme", "a", "admin", "-acme", "acme_corp"} {
		_, err := st.CreateTenant(ctx, store.Scope{UserID: a}, store.NewTenant{Slug: bad, Name: "x"}, a)
		var inv *store.InvalidError
		if !errors.As(err, &inv) {
			t.Errorf("slug %q: %v, want invalid", bad, err)
		}
	}
}

func TestLastOwnerStays(t *testing.T) {
	st, _ := setup(t)
	a := user(t, st, "a@acme.test")
	b := user(t, st, "b@acme.test")
	acme := tenant(t, st, a, "acme")
	sc := store.Scope{UserID: a}

	member := "member"
	if _, err := st.UpdateMember(ctx, sc, acme.ID, a, store.MemberPatch{TenantRole: &member}); err == nil {
		t.Fatal("the only owner was demoted")
	}
	if err := st.RemoveMember(ctx, sc, acme.ID, a); err == nil {
		t.Fatal("the only owner was removed")
	}
	if _, err := st.AddMember(ctx, sc, acme.ID, b, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateMember(ctx, sc, acme.ID, a, store.MemberPatch{TenantRole: &member}); err != nil {
		t.Fatalf("demoting one of two owners: %v", err)
	}
}

func TestAppsGrantsAndPlacement(t *testing.T) {
	st, pool := setup(t)
	op := store.Scope{Operator: true}
	_, changed, err := st.ApplyApp(ctx, op, devflow)
	if err != nil || !changed {
		t.Fatalf("apply: %v changed=%v", err, changed)
	}
	if _, changed, err := st.ApplyApp(ctx, op, devflow); err != nil || changed {
		t.Fatalf("re-apply: %v changed=%v, want no change", err, changed)
	}

	a := user(t, st, "a@acme.test")
	b := user(t, st, "b@acme.test")
	acme := tenant(t, st, a, "acme")
	sc := store.Scope{UserID: a}
	if _, err := st.AddMember(ctx, sc, acme.ID, b, "member"); err != nil {
		t.Fatal(err)
	}

	// grants need the app enabled
	if _, err := st.CreateGrant(ctx, sc, acme.ID, store.NewGrant{App: "devflow", UserID: b, Role: "operator"}); err == nil {
		t.Fatal("grant allowed before the app was enabled")
	}
	ta, err := st.EnableApp(ctx, sc, acme.ID, "devflow")
	if err != nil {
		t.Fatal(err)
	}
	if ta.Placement == nil || ta.Placement.Mode != "shared" || ta.Placement.Manager != "platform" ||
		ta.Placement.State != "requested" {
		t.Fatalf("placement %+v, want shared/platform/requested", ta.Placement)
	}
	if _, err := st.CreateGrant(ctx, sc, acme.ID, store.NewGrant{App: "devflow", UserID: b, Role: "nope"}); err == nil {
		t.Fatal("unknown role granted")
	}
	if _, err := st.CreateGrant(ctx, sc, acme.ID, store.NewGrant{App: "devflow", UserID: b, Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateGrant(ctx, sc, acme.ID, store.NewGrant{App: "devflow", UserID: b, Role: "operator"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate grant: %v", err)
	}

	// a role still granted cannot vanish from the manifest
	shrunk := devflow
	shrunk.Roles = []store.RoleDef{devflow.Roles[0], devflow.Roles[2]}
	if _, _, err := st.ApplyApp(ctx, op, shrunk); err == nil {
		t.Fatal("removed a role that is still granted")
	}

	// removing the member revokes the grant
	if err := st.RemoveMember(ctx, sc, acme.ID, b); err != nil {
		t.Fatal(err)
	}
	gs, err := st.ListGrants(ctx, sc, acme.ID, store.GrantFilter{})
	if err != nil || len(gs) != 0 {
		t.Fatalf("grants after removal: %v %v", gs, err)
	}

	// an enterprise plan that requires its own database wins over the default
	if _, err := pool.Exec(ctx, `INSERT INTO plan (id, name, data_mode_required) VALUES ('enterprise', 'Enterprise', 'database')`); err != nil {
		t.Fatal(err)
	}
	c := user(t, st, "c@globex.test")
	globex, err := st.CreateTenant(ctx, op, store.NewTenant{Slug: "globex", Name: "Globex", Plan: "enterprise"}, c)
	if err != nil {
		t.Fatal(err)
	}
	ta, err = st.EnableApp(ctx, store.Scope{UserID: c}, globex.ID, "devflow")
	if err != nil {
		t.Fatal(err)
	}
	if ta.Placement.Mode != "database" {
		t.Fatalf("enterprise placement mode %q, want database", ta.Placement.Mode)
	}
}

func TestEveryChangeIsVersionedAndInTheOutbox(t *testing.T) {
	st, pool := setup(t)
	a := user(t, st, "a@acme.test")
	acme := tenant(t, st, a, "acme")
	name := "Acme Corp"
	t2, err := st.UpdateTenant(ctx, store.Scope{UserID: a}, acme.ID, store.TenantPatch{Name: &name}, acme.Version)
	if err != nil {
		t.Fatal(err)
	}
	if t2.Version <= acme.Version {
		t.Fatalf("version did not move: %d -> %d", acme.Version, t2.Version)
	}
	if _, err := st.UpdateTenant(ctx, store.Scope{UserID: a}, acme.ID, store.TenantPatch{Name: &name}, acme.Version); !errors.Is(err, store.ErrVersion) {
		t.Fatalf("stale If-Match: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT type, version FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	last := int64(0)
	for rows.Next() {
		var typ string
		var v int64
		if err := rows.Scan(&typ, &v); err != nil {
			t.Fatal(err)
		}
		if v <= last {
			t.Errorf("outbox versions not increasing at %s", typ)
		}
		last = v
		types = append(types, typ)
	}
	want := []string{"matura.user.created", "matura.tenant.created", "matura.workspace.created",
		"matura.membership.added", "matura.tenant.updated"}
	if len(types) != len(want) {
		t.Fatalf("outbox %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("outbox %v, want %v", types, want)
		}
	}
	// an unchanged profile writes nothing
	if _, err := st.UpsertUser(ctx, store.UserProfile{ID: a, Email: "a@acme.test", EmailVerified: true,
		DisplayName: "a@acme.test"}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&n)
	if n != len(want) {
		t.Fatalf("unchanged profile emitted an event (%d rows)", n)
	}
}

func TestRevocationRevokes(t *testing.T) {
	user, agent, tenant, other := ids.New(), ids.New(), ids.New(), ids.New()
	at := time.Date(2026, 10, 18, 9, 0, 0, 500_000_000, time.UTC)
	sid := "s1"
	r := store.Revocation{UserID: user, NotBefore: at}
	tr := store.Revocation{UserID: user, TenantID: &tenant, NotBefore: at}
	sr := store.Revocation{UserID: user, SessionID: &sid, NotBefore: at}
	ar := store.Revocation{UserID: agent, NotBefore: at}
	before, same, after := at.Add(-time.Minute), at.Truncate(time.Second), at.Add(time.Second)
	cases := []struct {
		name          string
		r             store.Revocation
		sub, act, tid uuid.UUID
		sid           string
		iat           time.Time
		want          bool
	}{
		{"older token", r, user, uuid.Nil, other, "", before, true},
		{"issued in the same second (iat is whole seconds)", r, user, uuid.Nil, other, "", same, true},
		{"newer token", r, user, uuid.Nil, other, "", after, false},
		{"another user", r, other, uuid.Nil, tenant, "", before, false},
		{"tenant: same tenant", tr, user, uuid.Nil, tenant, "", before, true},
		{"tenant: another tenant", tr, user, uuid.Nil, other, "", before, false},
		{"tenant: token without tid", tr, user, uuid.Nil, uuid.Nil, "", before, false},
		{"session: same session", sr, user, uuid.Nil, tenant, "s1", before, true},
		{"session: another session", sr, user, uuid.Nil, tenant, "s2", before, false},
		{"agent: its own token", ar, agent, uuid.Nil, tenant, "", before, true},
		{"agent: acting for a person", ar, user, agent, tenant, "", before, true},
	}
	for _, c := range cases {
		if got := c.r.Revokes(c.sub, c.act, c.tid, c.sid, c.iat); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
