package matura_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	matura "github.com/marunsct/Platform/sdk/go"
	"github.com/marunsct/Platform/sdk/go/maturatest"
)

const (
	T1 = "0192b7a4-6000-7000-8000-000000000001"
	T2 = "0192b7a4-6000-7000-8000-000000000002"
	U1 = "0192b7a4-5c1e-7d2a-9f00-4b1e2a9c0d11"
)

func ev(id, typ, obj string, version int64, payload map[string]any) *matura.Event {
	raw, _ := json.Marshal(payload)
	return &matura.Event{ID: id, Type: "matura." + typ, Data: matura.EventData{Object: obj, Version: version, Payload: raw}}
}

func inTx(t *testing.T, db matura.TxBeginner, fn func(tx pgx.Tx) error) error {
	t.Helper()
	return pgx.BeginFunc(context.Background(), db, fn)
}

func TestDDLMatchesDocs(t *testing.T) {
	if matura.PostgresSQL != string(repoFile(t, "docs/contract/sql/postgres.sql")) {
		t.Error("sql/postgres.sql differs from docs/contract/sql/postgres.sql; copy it")
	}
	if matura.PostgresSharedRLSSQL != string(repoFile(t, "docs/contract/sql/postgres-shared-rls.sql")) {
		t.Error("sql/postgres-shared-rls.sql differs from docs/contract/sql/postgres-shared-rls.sql; copy it")
	}
	if n := len(matura.DDL(false)); n != 12 {
		t.Errorf("DDL statements = %d", n)
	}
	rls := matura.DDL(true)
	if len(rls) != 32 || !strings.HasPrefix(rls[31], "CREATE POLICY tenant_isolation ON matura_user") {
		t.Errorf("RLS statements = %d", len(rls))
	}
	for _, s := range rls {
		if strings.Contains(s, "--") {
			t.Errorf("comment left in %q", s)
		}
	}
}

func TestCreateIsIdempotent(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	if err := matura.NewContract().Create(ctx, pool, true); err != nil {
		t.Fatal(err)
	}
	var v string
	if err := pool.QueryRow(ctx, `SELECT version FROM matura_contract`).Scan(&v); err != nil || v != matura.ContractVersion {
		t.Fatalf("contract version = %q, %v", v, err)
	}
}

func TestOrderAndDuplicatesDoNotMatter(t *testing.T) {
	events := loadVectors(t).Apply.Events
	var want []map[string]any
	for i := range 4 {
		pool, _ := contractDB(t)
		c := matura.NewContract()
		shuffled := append([]*matura.Event{}, events...)
		if i > 0 {
			rand.New(rand.NewSource(int64(i))).Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		}
		// a rename must follow the grant events before it (they arrive in commit order), so keep it last
		for j, e := range shuffled {
			if e.Data.Object == "app_role" && strings.Contains(string(e.Data.Payload), "previous_name") {
				shuffled = append(append(shuffled[:j:j], shuffled[j+1:]...), e)
				break
			}
		}
		err := inTx(t, pool, func(tx pgx.Tx) error {
			for _, e := range append(shuffled, shuffled...) {
				if _, err := c.Apply(context.Background(), tx, e); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got := rowsJSON(t, pool, `SELECT t.id, t.name, t.data_mode, t.version, t.placement_version,
			(SELECT json_agg(m ORDER BY m.user_id) FROM matura_membership m WHERE m.tenant_id = t.id) AS members
			FROM matura_tenant t ORDER BY t.id`)
		if i == 0 {
			want = got
		} else if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("order %d:\n got %v\nwant %v", i, got, want)
		}
	}
}

func TestHooksInboxAndRollback(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	var seen []string
	c.On("membership", func(ctx context.Context, db matura.Executor, e *matura.Event) error {
		var m struct {
			TenantRole string `json:"tenant_role"`
		}
		if err := e.Decode(&m); err != nil {
			return err
		}
		seen = append(seen, "membership:"+m.TenantRole)
		return nil
	})
	c.On("matura.tenant.deleting", func(ctx context.Context, db matura.Executor, e *matura.Event) error {
		return errors.New("cannot delete yet")
	})
	c.On("*", func(ctx context.Context, db matura.Executor, e *matura.Event) error {
		seen = append(seen, "*:"+e.Type)
		return nil
	})
	m := ev("evt_1", "membership.added", "membership", 5, map[string]any{"tenant_id": T1, "user_id": U1,
		"tenant_role": "admin", "status": "active", "joined_at": "2026-10-17T09:00:00Z"})
	for i, want := range []bool{true, false} {
		err := inTx(t, pool, func(tx pgx.Tx) error {
			ok, err := c.Apply(ctx, tx, m)
			if ok != want {
				t.Errorf("apply %d = %v", i, ok)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(seen) != "[membership:admin *:matura.membership.added]" {
		t.Fatalf("hooks = %v", seen)
	}
	// the hook's error rolls back the inbox row and the upsert with the caller's transaction
	del := ev("evt_2", "tenant.deleting", "tenant", 9, map[string]any{"id": T1, "slug": "acme", "name": "Acme",
		"status": "deleting"})
	err := inTx(t, pool, func(tx pgx.Tx) error { _, err := c.Apply(ctx, tx, del); return err })
	if err == nil || err.Error() != "cannot delete yet" {
		t.Fatalf("err = %v", err)
	}
	var status string
	var inbox int
	_ = pool.QueryRow(ctx, `SELECT status FROM matura_tenant`).Scan(&status)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM matura_inbox`).Scan(&inbox)
	if status != "active" || inbox != 1 {
		t.Fatalf("status = %s, inbox = %d", status, inbox)
	}
}

func TestInvalidEventWritesNothing(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	for _, e := range []*matura.Event{
		ev("evt_1", "membership.added", "membership", 5, map[string]any{"tenant_id": T1, "user_id": U1, "status": "active"}),
		ev("evt_2", "user.updated", "user", 5, map[string]any{"id": "not-a-uuid", "status": "active"}),
		ev("evt_3", "tenant.updated", "tenant", 5, map[string]any{"id": T1, "slug": "a", "name": "A", "status": "active",
			"updated_at": "yesterday"}),
		ev("evt_4", "app.role.updated", "app_role", 5, map[string]any{"role": map[string]any{"permissions": []string{}}}),
	} {
		err := inTx(t, pool, func(tx pgx.Tx) error { _, err := c.Apply(ctx, tx, e); return err })
		if !errors.Is(err, matura.ErrInvalidEvent) {
			t.Errorf("%s: err = %v", e.ID, err)
		}
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM matura_inbox) + (SELECT count(*) FROM matura_tenant)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows written", n)
	}
	// objects the contract has no table for only run hooks
	ok, err := c.Apply(ctx, pool, ev("evt_5", "tenant_app.enabled", "tenant_app", 5, map[string]any{"tenant_id": T1}))
	if err != nil || !ok {
		t.Fatalf("tenant_app: %v %v", ok, err)
	}
}

func TestPrincipalRowsAreFilledInByEvents(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	iss := newIssuer(t)
	p, err := iss.Verifier().Verify(ctx, mustToken(t, iss, maturatest.TokenOptions{UserID: U1, TenantID: T1,
		Tenant: "acme", TenantRoles: []string{"admin"}, Email: "ada@example.test"}))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.ApplyPrincipal(ctx, pool, p); err != nil {
			t.Fatal(err)
		}
	}
	got := rowsJSON(t, pool, `SELECT t.slug, t.version, u.email, m.tenant_role FROM matura_tenant t, matura_user u,
		matura_membership m`)
	if fmt.Sprint(got) != "[map[email:ada@example.test slug:acme tenant_role:admin version:0]]" {
		t.Fatalf("rows = %v", got)
	}
	_, err = c.Apply(ctx, pool, ev("evt_1", "tenant.updated", "tenant", 3, map[string]any{"id": T1, "slug": "acme",
		"name": "Acme Inc", "status": "active", "data_mode_default": "shared"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := rowsJSON(t, pool, `SELECT name, version FROM matura_tenant`); fmt.Sprint(got) != "[map[name:Acme Inc version:3]]" {
		t.Fatalf("rows = %v", got)
	}
	if len(c.FromPrincipal(&matura.Principal{UserID: U1})) != 0 {
		t.Fatal("rows for a token without a tenant")
	}
}

func TestCursorAndPrune(t *testing.T) {
	pool, _ := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	if cur, err := c.Cursor(ctx, pool, ""); err != nil || cur != "" {
		t.Fatalf("cursor = %q, %v", cur, err)
	}
	for _, cur := range []string{"10", "42"} {
		if err := c.SaveCursor(ctx, pool, cur, ""); err != nil {
			t.Fatal(err)
		}
	}
	if cur, err := c.Cursor(ctx, pool, "changes"); err != nil || cur != "42" {
		t.Fatalf("cursor = %q, %v", cur, err)
	}
	_, _ = pool.Exec(ctx, `INSERT INTO matura_inbox VALUES ('old', now() - interval '8 days'), ('new', now())`)
	if err := c.PruneInbox(ctx, pool, 0); err != nil {
		t.Fatal(err)
	}
	if got := rowsJSON(t, pool, `SELECT event_id FROM matura_inbox`); fmt.Sprint(got) != "[map[event_id:new]]" {
		t.Fatalf("inbox = %v", got)
	}
}

// TestWithTenantIsolates: in shared mode a runtime role without BYPASSRLS sees only the tenant set per transaction.
func TestWithTenantIsolates(t *testing.T) {
	pool, dbURL := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	for i, tid := range []string{T1, T2} {
		e := ev(fmt.Sprint("evt_", i), "membership.added", "membership", 5, map[string]any{"tenant_id": tid,
			"user_id": U1, "tenant_role": "member", "status": "active"})
		if _, err := c.Apply(ctx, pool, e); err != nil {
			t.Fatal(err)
		}
	}
	role := randomName("matura_sdk_app_")
	for _, q := range []string{
		`CREATE ROLE ` + role + ` LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'x'`,
		`GRANT SELECT ON ALL TABLES IN SCHEMA public TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { // roles belong to the server, not the test database
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE `+role)
	})
	u, _ := url.Parse(dbURL)
	u.User = url.UserPassword(role, "x")
	app, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	count := func(tx pgx.Tx) string {
		var tenants, members, users int
		_ = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM matura_tenant), (SELECT count(*) FROM matura_membership),
			(SELECT count(*) FROM matura_user)`).Scan(&tenants, &members, &users)
		return fmt.Sprint(tenants, members, users)
	}
	var got string
	err = matura.WithTenant(ctx, app, T1, func(tx pgx.Tx) error {
		got = count(tx)
		var tid string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM matura_tenant`).Scan(&tid); err != nil || tid != T1 {
			return fmt.Errorf("tenant %s: %v", tid, err)
		}
		return nil
	})
	if err != nil || got != "1 1 1" {
		t.Fatalf("scoped: %s, %v", got, err)
	}
	if err := inTx(t, app, func(tx pgx.Tx) error { got = count(tx); return nil }); err != nil || got != "0 0 0" {
		t.Fatalf("unscoped: %s, %v", got, err)
	}
	if err := matura.WithTenant(ctx, app, "", func(pgx.Tx) error { return nil }); !errors.Is(err, matura.ErrNoTenant) {
		t.Fatalf("no tenant: %v", err)
	}
	// the tenant of the request's principal
	rctx := matura.WithPrincipal(ctx, &matura.Principal{TenantID: T2})
	err = matura.WithPrincipalTenant(rctx, app, func(tx pgx.Tx) error {
		var tid string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM matura_tenant`).Scan(&tid); err != nil || tid != T2 {
			return fmt.Errorf("tenant %s: %v", tid, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
