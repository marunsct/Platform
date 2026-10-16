package ids

import "testing"

func TestValidSlug(t *testing.T) {
	for _, s := range []string{"acme", "acme-corp", "a1b", "x0-y0-z0"} {
		if !ValidSlug(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "ab", "Acme", "-acme", "acme-", "acme_corp", "admin", "postgres",
		"a-very-long-slug-that-goes-beyond-forty-chars"} {
		if ValidSlug(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestNewIsTimeOrdered(t *testing.T) {
	a, b := New(), New()
	if a.Version() != 7 || b.String() <= a.String() {
		t.Fatalf("not UUIDv7 in order: %s %s", a, b)
	}
}
