package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/portal"
)

// TestPortalServed checks maturad serves the embedded portal: index, hashed assets, SPA fallback for client routes,
// the runtime configuration, and a strict Content-Security-Policy on all of it.
func TestPortalServed(t *testing.T) {
	server := api.New(nil, nil, nil, nil)
	server.SetPortal(portal.Config{Auth: "oidc", Issuer: "https://id.example.com/realms/matura", ClientID: "matura-console"})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	get := func(path string) (*http.Response, string) {
		t.Helper()
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	strictCSP := func(path string, res *http.Response) {
		t.Helper()
		csp := res.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self';", "style-src 'self';",
			"connect-src 'self' https://id.example.com;", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-") {
			t.Errorf("%s: CSP allows unsafe sources: %q", path, csp)
		}
		if res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", path)
		}
	}

	res, index := get("/portal/")
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("/portal/: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	strictCSP("/portal/", res)
	if res.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("index Cache-Control = %q", res.Header.Get("Cache-Control"))
	}
	if strings.Contains(index, "<script>") || strings.Contains(index, "<style") {
		t.Error("index.html has inline script or style, which the CSP would block")
	}
	asset := regexp.MustCompile(`/portal/assets/[A-Za-z0-9_-]+\.js`).FindString(index)
	if asset == "" {
		t.Fatalf("index.html references no script: %s", index)
	}

	res, body := get(asset)
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Content-Type"), "javascript") || len(body) == 0 {
		t.Fatalf("%s: %d %s", asset, res.StatusCode, res.Header.Get("Content-Type"))
	}
	if !strings.Contains(res.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("asset Cache-Control = %q", res.Header.Get("Cache-Control"))
	}
	strictCSP(asset, res)

	for _, path := range []string{"/portal/t/0b9e3b8e-8f5c-4a43-9a32-6c1d2c55d0a1/members", "/portal/account", "/portal/callback?code=x&state=y"} {
		res, body := get(path)
		if res.StatusCode != http.StatusOK || body != index {
			t.Errorf("%s: want the SPA index, got %d", path, res.StatusCode)
		}
		strictCSP(path, res)
	}
	for _, path := range []string{"/portal/assets/missing.js", "/portal/nope.css"} {
		if res, _ := get(path); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404 rather than the index", path, res.StatusCode)
		}
	}
	if res, _ := get("/portal"); res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != "/portal/" {
		t.Errorf("/portal: %d to %q, want a redirect to /portal/", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := get("/portal/../v1/me"); res.StatusCode == http.StatusOK {
		t.Error("path traversal reached outside the portal")
	}

	res, body = get("/portal/config.json")
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("config.json: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("config.json Cache-Control = %q", res.Header.Get("Cache-Control"))
	}
	var cfg map[string]string
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"auth": "oidc", "issuer": "https://id.example.com/realms/matura", "client_id": "matura-console", "product": "Matura"}
	for k, v := range want {
		if cfg[k] != v {
			t.Errorf("config.json %s = %q, want %q", k, cfg[k], v)
		}
	}
}
