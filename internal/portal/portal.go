// Package portal serves the customer portal (web/portal, built into dist/) at /portal/ with its runtime
// configuration and a strict Content-Security-Policy. The build output is committed so `go build` needs no Node.
package portal

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Prefix is where the portal is mounted.
const Prefix = "/portal/"

// Config is what the portal's browser code needs at run time, served as /portal/config.json.
type Config struct {
	Auth     string `json:"auth"`      // oidc, or dev when maturad trusts X-Matura-Dev-* headers
	Issuer   string `json:"issuer"`    // OIDC issuer (Keycloak realm URL) the browser signs in with
	ClientID string `json:"client_id"` // public client, authorization code with PKCE
	Product  string `json:"product"`   // name shown in the portal
}

type Portal struct {
	cfg    Config
	files  fs.FS
	index  []byte
	csp    string
	config []byte
}

// New prepares the portal. A missing build (dist without index.html) still serves a short page saying so.
func New(cfg Config) *Portal {
	if cfg.Auth == "" {
		cfg.Auth = "oidc"
	}
	if cfg.Product == "" {
		cfg.Product = "Matura"
	}
	files, _ := fs.Sub(dist, "dist")
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		index = []byte("<!doctype html><title>Matura</title><p>The portal is not built. Run <code>make portal</code>.</p>")
	}
	conf, _ := json.Marshal(cfg)
	return &Portal{cfg: cfg, files: files, index: index, config: conf, csp: csp(cfg.Issuer)}
}

// csp allows only the portal's own files, and network calls to maturad and the identity provider.
func csp(issuer string) string {
	connect := "'self'"
	if o := originOf(issuer); o != "" {
		connect += " " + o
	}
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
		"connect-src " + connect + "; manifest-src 'self'; base-uri 'none'; form-action 'none'; " +
		"frame-ancestors 'none'; object-src 'none'"
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (p *Portal) secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", p.csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer") // the sign-in callback URL carries a one-time code
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}

// ConfigJSON serves GET /portal/config.json.
func (p *Portal) ConfigJSON(w http.ResponseWriter, r *http.Request) {
	p.secure(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(p.config)
}

// Files serves GET /portal/…: built files, and index.html for any other path so the browser router can take it.
func (p *Portal) Files(w http.ResponseWriter, r *http.Request) {
	p.secure(w)
	name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, Prefix)), "/")
	if name != "" && name != "index.html" {
		if st, err := fs.Stat(p.files, name); err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // names carry a content hash
			} else {
				w.Header().Set("Cache-Control", "public, max-age=3600")
			}
			http.ServeFileFS(w, r, p.files, name)
			return
		}
		// a missing script or stylesheet is a 404, not the app's HTML
		if strings.HasPrefix(name, "assets/") || path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(p.index)
}
