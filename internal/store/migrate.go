package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies pending migrations in file-name order, each in its own transaction, under an advisory lock so
// several maturad replicas starting together do not race. It then grants the runtime role access to every table,
// so tables added by later migrations are covered too.
func Migrate(ctx context.Context, conn *pgx.Conn, runtimeRole string) error {
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7351001)`); err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7351001)`) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).
			Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, err := migrationFiles.ReadFile(name)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	if runtimeRole == "" {
		return nil
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, runtimeRole).
		Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("runtime role %q does not exist; create it (LOGIN, NOBYPASSRLS) before starting maturad", runtimeRole)
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + role,
		`REVOKE ALL ON schema_migrations FROM ` + role,
		// the audit log is append-only (technical specification §13)
		`REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM ` + role,
		// retention deletes only through this function, which decides what may go (§14.4)
		`GRANT EXECUTE ON FUNCTION matura_audit_purge(uuid) TO ` + role,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + role,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("granting runtime role: %w", err)
		}
	}
	return nil
}
