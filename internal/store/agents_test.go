package store_test

import (
	"slices"
	"testing"

	"github.com/marunsct/Platform/internal/store"
)

// TestIntersectPerms: a delegated token gets what both the person and the agent may do (TS15).
func TestIntersectPerms(t *testing.T) {
	for _, c := range []struct{ a, b, want []string }{
		{[]string{"run.start", "workflow.read"}, []string{"workflow.read", "workflow.write"}, []string{"workflow.read"}},
		{[]string{"*"}, []string{"workflow.write", "run.start"}, []string{"run.start", "workflow.write"}},
		{[]string{"workflow.read"}, []string{"*"}, []string{"workflow.read"}},
		{[]string{"*"}, []string{"*"}, []string{"*"}},
		{[]string{"a.b"}, []string{}, []string{}},
		{[]string{}, []string{"*"}, []string{}},
	} {
		if got := store.IntersectPerms(c.a, c.b); !slices.Equal(got, c.want) {
			t.Errorf("IntersectPerms(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
