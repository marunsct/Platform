package api

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := s.clientIP(r).String(); got != "10.0.0.5" {
		t.Fatalf("untrusted proxy: X-Forwarded-For believed (%s)", got)
	}
	s.SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9, 10.0.0.7")
	if got := s.clientIP(r).String(); got != "203.0.113.9" {
		t.Fatalf("behind trusted proxies: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "garbage")
	if got := s.clientIP(r).String(); got != "10.0.0.5" {
		t.Fatalf("unparsable hop: %s", got)
	}
}

func TestRequestID(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-Id", "abc-123")
	if requestID(r) != "abc-123" {
		t.Fatal("caller's request id not kept")
	}
	r.Header.Set("X-Request-Id", "has space")
	if id := requestID(r); !strings.HasPrefix(id, "req_") {
		t.Fatalf("unsafe request id kept: %q", id)
	}
}
