// Package testdb gives integration tests a fresh, migrated control-plane database.
//
// Set MATURA_TEST_DATABASE_URL to a superuser connection (scripts/test-postgres.sh starts one). Each call creates a
// new database owned by a non-superuser owner role, migrates it, and returns a pool connected as the runtime role,
// which has no BYPASSRLS, exactly as in production. Without the variable the tests are skipped.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/store"
)

const (
	ownerRole   = "matura_test_owner"
	runtimeRole = "matura_test_app"
	password    = "matura-test"
)

func withUser(raw, user, db string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.User = url.UserPassword(user, password)
	u.Path = "/" + db
	return u.String()
}

// New returns a pool for the runtime role on a fresh database.
func New(t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin := os.Getenv("MATURA_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("MATURA_TEST_DATABASE_URL is not set; run: eval \"$(scripts/test-postgres.sh)\"")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to test server: %v", err)
	}
	defer conn.Close(ctx)

	for _, role := range []string{ownerRole, runtimeRole} {
		_, err := conn.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
				CREATE ROLE %[1]s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%[2]s';
			END IF; END $$`, role, password))
		if err != nil {
			t.Fatalf("create role %s: %v", role, err)
		}
	}
	db := "matura_test_" + strings.ReplaceAll(ids.New().String(), "-", "")[:20]
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+db+` OWNER `+ownerRole); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), admin)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), `DROP DATABASE IF EXISTS `+db+` WITH (FORCE)`)
	})

	owner, err := pgx.Connect(ctx, withUser(admin, ownerRole, db))
	if err != nil {
		t.Fatalf("connect as owner: %v", err)
	}
	// public is owned by pg_database_owner (Postgres 15+), so the database owner can create the tables
	err = store.Migrate(ctx, owner, runtimeRole)
	owner.Close(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := store.Open(ctx, withUser(admin, runtimeRole, db))
	if err != nil {
		t.Fatalf("runtime pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
