package matura_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	matura "github.com/marunsct/Platform/sdk/go"
)

func repoFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type vectors struct {
	Secret     string `json:"secret"`
	Signatures []struct {
		Name   string `json:"name"`
		Body   string `json:"body"`
		Header string `json:"header"`
		Now    int64  `json:"now"`
		Valid  bool   `json:"valid"`
	} `json:"signatures"`
	Tokens struct {
		Issuer   string      `json:"issuer"`
		Audience string      `json:"audience"`
		Now      int64       `json:"now"`
		JWKS     matura.JWKS `json:"jwks"`
		Cases    []struct {
			Name      string `json:"name"`
			Token     string `json:"token"`
			Valid     bool   `json:"valid"`
			Principal struct {
				UserID        string   `json:"user_id"`
				TenantID      *string  `json:"tenant_id"`
				TenantSlug    *string  `json:"tenant_slug"`
				WorkspaceID   *string  `json:"workspace_id"`
				TenantRoles   []string `json:"tenant_roles"`
				Roles         []string `json:"roles"`
				Permissions   []string `json:"permissions"`
				Email         string   `json:"email"`
				PlacementMode *string  `json:"placement_mode"`
				Kind          string   `json:"kind"`
				Actor         *struct {
					Sub      string `json:"sub"`
					Kind     string `json:"kind"`
					ClientID string `json:"client_id"`
				} `json:"actor"`
				Has map[string]bool `json:"has"`
			} `json:"principal"`
		} `json:"cases"`
	} `json:"tokens"`
	Apply struct {
		Events  []*matura.Event             `json:"events"`
		Applied []bool                      `json:"applied"`
		Rows    map[string][]map[string]any `json:"rows"`
	} `json:"apply"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	var v vectors
	if err := json.Unmarshal(repoFile(t, "docs/contract/test-vectors.json"), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func randomName(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// testDB returns a pool on a fresh database (owned by the test server's user) and its URL. Set
// MATURA_TEST_DATABASE_URL to a superuser connection; without it the test is skipped.
func testDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	admin := os.Getenv("MATURA_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("MATURA_TEST_DATABASE_URL is not set; run: eval \"$(scripts/test-postgres.sh)\" in the repository root")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to test server: %v", err)
	}
	defer conn.Close(ctx)
	db := randomName("matura_sdk_")
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+db); err != nil {
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
	u, _ := url.Parse(admin)
	u.Path = "/" + db
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, u.String()
}

// contractDB is testDB with the contract tables (and shared-mode RLS) created.
func contractDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	pool, u := testDB(t)
	if err := matura.NewContract().Create(context.Background(), pool, true); err != nil {
		t.Fatal(err)
	}
	return pool, u
}

// rowsJSON returns the rows of a query as JSON values, for comparing with expected rows.
func rowsJSON(t *testing.T, db matura.Executor, sql string) []map[string]any {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(context.Background(), `SELECT coalesce(json_agg(r), '[]') FROM (`+sql+`) r`).Scan(&raw); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
