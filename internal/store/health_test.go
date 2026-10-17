package store_test

import (
	"context"
	"testing"
)

func TestBacklog(t *testing.T) {
	st, _ := setup(t)
	owner := user(t, st, "owner@example.test")
	tenant(t, st, owner, "acme") // creating a tenant emits changes that wait for the sequencer
	b, err := st.Backlog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.UnsequencedEvents == 0 || b.EmailsPending != 0 || b.WebhookLag != 0 {
		t.Fatalf("backlog: %+v", b)
	}
}
