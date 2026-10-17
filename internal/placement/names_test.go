package placement

import (
	"strings"
	"testing"
)

func TestIdent(t *testing.T) {
	cases := map[string][]string{
		"devflow_t_acme_corp": {"devflow", "t", "acme-corp"},
		"my_app_shared":       {"My-App", "shared"},
		"a_b_c":               {"a;b", "c"},
	}
	for want, parts := range cases {
		if got := ident(parts...); got != want {
			t.Errorf("ident(%v) = %q, want %q", parts, got, want)
		}
	}
	long := ident("app", "t", strings.Repeat("x", 80))
	if len(long) != 63 {
		t.Errorf("long name is %d bytes, want 63", len(long))
	}
}
