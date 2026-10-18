package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marunsct/Platform/internal/store"
)

// The leader loops each hold a connection; the pool must still have room for requests when all of them lead.
func TestOpenLeavesRoomBesideLeaders(t *testing.T) {
	url := "postgres://u:p@localhost:1/db?sslmode=disable"
	def, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(context.Background(), url) // connects lazily, so no server is needed
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if got := pool.Config().MaxConns; got != def.MaxConns+store.LeaderConns {
		t.Fatalf("max conns %d, want %d", got, def.MaxConns+store.LeaderConns)
	}
	set, err := store.Open(context.Background(), url+"&pool_max_conns=3")
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	if got := set.Config().MaxConns; got != 3 {
		t.Fatalf("explicit pool_max_conns overridden: %d", got)
	}
}
