package matura_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	matura "github.com/marunsct/Platform/sdk/go"
)

// The shared vectors (docs/contract/test-vectors.json) that every Matura SDK runs.

func TestSignatureVectors(t *testing.T) {
	v := loadVectors(t)
	for _, s := range v.Signatures {
		t.Run(s.Name, func(t *testing.T) {
			err := matura.VerifySignature([]byte(v.Secret), s.Header, []byte(s.Body), time.Unix(s.Now, 0))
			if (err == nil) != s.Valid {
				t.Fatalf("valid = %v, err = %v", s.Valid, err)
			}
			if err != nil && !errors.Is(err, matura.ErrBadSignature) {
				t.Fatalf("err = %v, want matura.ErrBadSignature", err)
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestTokenVectors(t *testing.T) {
	v := loadVectors(t).Tokens
	jwks := v.JWKS
	verifier, err := matura.NewVerifier(matura.VerifierOptions{Issuer: v.Issuer, Audience: v.Audience, JWKS: &jwks,
		Now: func() time.Time { return time.Unix(v.Now, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			p, err := verifier.Verify(context.Background(), c.Token)
			if !c.Valid {
				if !errors.Is(err, matura.ErrInvalidToken) {
					t.Fatalf("err = %v, want matura.ErrInvalidToken", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			w := c.Principal
			got := []any{p.UserID, p.TenantID, p.TenantSlug, p.WorkspaceID, p.TenantRoles, p.Roles, p.Permissions,
				p.Email, p.PlacementMode}
			want := []any{w.UserID, deref(w.TenantID), deref(w.TenantSlug), deref(w.WorkspaceID), w.TenantRoles, w.Roles,
				w.Permissions, w.Email, deref(w.PlacementMode)}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("principal = %v, want %v", got, want)
			}
			if p.Kind != w.Kind {
				t.Errorf("kind = %q, want %q", p.Kind, w.Kind)
			}
			switch {
			case w.Actor == nil && p.Actor != nil:
				t.Errorf("actor = %+v, want none", p.Actor)
			case w.Actor != nil && (p.Actor == nil ||
				*p.Actor != (matura.Actor{Sub: w.Actor.Sub, Kind: w.Actor.Kind, ClientID: w.Actor.ClientID})):
				t.Errorf("actor = %+v, want %+v", p.Actor, *w.Actor)
			}
			for perm, ok := range w.Has {
				if p.Has(perm) != ok {
					t.Errorf("Has(%q) = %v", perm, !ok)
				}
			}
		})
	}
}

func TestApplyVectors(t *testing.T) {
	v := loadVectors(t).Apply
	pool, _ := contractDB(t)
	ctx := context.Background()
	c := matura.NewContract()
	var applied []bool
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, e := range v.Events {
			ok, err := c.Apply(ctx, tx, e)
			if err != nil {
				return err
			}
			applied = append(applied, ok)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(applied, v.Applied) {
		t.Fatalf("applied = %v, want %v", applied, v.Applied)
	}
	tables := make([]string, 0, len(v.Rows))
	for table := range v.Rows {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		want := v.Rows[table]
		cols := columns(t, want)
		got := rowsJSON(t, pool, "SELECT "+strings.Join(cols, ", ")+" FROM "+table+" ORDER BY "+strings.Join(cols[:orderBy(table)], ", "))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", table, got, want)
		}
	}
}

// columns returns the expected rows' columns in the order the generator selected them (ids first).
func columns(t *testing.T, rows []map[string]any) []string {
	t.Helper()
	order := []string{"id", "name", "tenant_id", "user_id", "slug", "email", "display_name", "workspace_id",
		"subject_id", "kind", "tenant_role", "role", "permissions", "is_default", "status", "plan", "data_mode",
		"version", "placement_version"}
	var cols []string
	for _, c := range order {
		if _, ok := rows[0][c]; ok {
			cols = append(cols, c)
		}
	}
	if len(cols) != len(rows[0]) {
		t.Fatalf("unknown columns in %v", rows[0])
	}
	return cols
}

func orderBy(table string) int {
	if table == "matura_membership" {
		return 2 // tenant_id, user_id
	}
	return 1
}
