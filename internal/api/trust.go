package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/marunsct/Platform/internal/readiness"
)

// Trust page (TS25, technical specification §14.4): the installation's public security posture, from the readiness
// controls marked public. Off unless MATURA_TRUST_PAGE=on; rendered on request and kept for five minutes.

const trustTTL = 5 * time.Minute

const trustCSS = `:root{color-scheme:light dark;--fg:#1a1d21;--muted:#5b636e;--bg:#fff;--line:#e3e6ea;--ok:#0f7a3d;--no:#a3361b;--na:#5b636e}
@media (prefers-color-scheme:dark){:root{--fg:#e8eaed;--muted:#a1a8b3;--bg:#15171a;--line:#2b2f35;--ok:#4cc37f;--no:#f08a6c;--na:#a1a8b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:46rem;margin:0 auto;padding:2.5rem 1rem}h1{font-size:1.75rem;margin:0 0 .5rem}.lead{font-size:1.125rem;margin:0 0 .25rem}
.muted{color:var(--muted);font-size:.875rem}a{color:inherit}.controls{list-style:none;padding:0;margin:2rem 0;border-top:1px solid var(--line)}
.controls li{display:flex;gap:1rem;align-items:flex-start;padding:.875rem 0;border-bottom:1px solid var(--line)}
.controls small{display:block;color:var(--muted);font-size:.8125rem;margin-top:.125rem}
.badge{flex:0 0 7.5rem;font-size:.8125rem;font-weight:600}.in-place .badge{color:var(--ok)}.not-in-place .badge{color:var(--no)}.not-applicable .badge{color:var(--na)}
.notice{margin-top:2rem}`

var (
	//go:embed trust.html
	trustHTML string
	trustTmpl = template.Must(template.New("trust").Funcs(template.FuncMap{"statusText": func(s string) string {
		switch s {
		case "in-place":
			return "In place"
		case "not-in-place":
			return "Not in place"
		}
		return "Not applicable"
	}}).Parse(trustHTML))
	trustCSP = func() string {
		sum := sha256.Sum256([]byte(trustCSS))
		return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; " +
			"img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	}()
)

type trustCache struct {
	mu   sync.Mutex
	at   time.Time
	html []byte
	json []byte
}

func (c *trustCache) reset() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

// render returns the page and its JSON, rendering them again when older than trustTTL.
func (s *Server) renderTrust(r *http.Request) (page, doc []byte, err error) {
	c := &s.trust
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < trustTTL {
		return c.html, c.json, nil
	}
	rep, err := s.report(r.Context())
	if err != nil {
		return nil, nil, err
	}
	t := readiness.Public(rep, s.install.SecurityContact)
	var b bytes.Buffer
	if err := trustTmpl.Execute(&b, map[string]any{"T": t, "CSS": template.CSS(trustCSS),
		"Checked": t.GeneratedAt.Format("2006-01-02 15:04")}); err != nil {
		return nil, nil, err
	}
	j, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	c.html, c.json, c.at = b.Bytes(), append(j, '\n'), time.Now()
	return c.html, c.json, nil
}

func (s *Server) trustPage(asJSON bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.install.TrustPage {
			problem(w, http.StatusNotFound, "not-found", "the trust page is turned off on this installation")
			return
		}
		page, doc, err := s.renderTrust(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "public, max-age=300")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if asJSON {
			h.Set("Content-Type", "application/json")
			h.Set("Access-Control-Allow-Origin", "*")
			_, _ = w.Write(doc)
			return
		}
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", trustCSP)
		_, _ = w.Write(page)
	}
}
