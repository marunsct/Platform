package matura

import (
	_ "embed"
	"strings"
)

// PostgresSQL is docs/contract/sql/postgres.sql (the tests check the copy is identical).
//
//go:embed sql/postgres.sql
var PostgresSQL string

// PostgresSharedRLSSQL is docs/contract/sql/postgres-shared-rls.sql: row-level security for shared mode.
//
//go:embed sql/postgres-shared-rls.sql
var PostgresSharedRLSSQL string

// DDL returns the contract DDL for PostgreSQL as separate statements. rls adds the shared-mode policies.
func DDL(rls bool) []string {
	sql := stripComments(PostgresSQL)
	if rls {
		sql += stripComments(PostgresSharedRLSSQL)
	}
	var out []string
	for _, s := range strings.Split(sql, ";") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func stripComments(sql string) string {
	var keep []string
	for _, l := range strings.Split(sql, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "--") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
