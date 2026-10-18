package api

import (
	"net/http"
	"net/url"
	"strings"
)

// maturad's API as an OAuth 2.0 protected resource (RFC 9728, TS15): MCP clients and agents discover from the
// metadata which authorisation server (the Keycloak realm) issues tokens for it.

// SetProtectedResource sets maturad's resource identifier (its public URL), the token audience its API accepts
// (MATURA_AUDIENCE; agents may ask Keycloak for a token with this audience) and the realm's issuer URL.
func (s *Server) SetProtectedResource(resource, audience, issuer string) {
	s.resource, s.apiAudience = strings.TrimRight(resource, "/"), audience
	if s.issuer == "" {
		s.issuer = strings.TrimRight(issuer, "/")
	}
}

// ResourceMetadataURL is where RFC 9728 §3.1 puts the metadata of a resource: the well-known path inserted between
// the host and the resource's path.
func ResourceMetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return ""
	}
	path := strings.TrimRight(u.Path, "/")
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/.well-known/oauth-protected-resource"+path, "", "", ""
	return u.String()
}

func (s *Server) protectedResource(w http.ResponseWriter, r *http.Request) {
	if s.resource == "" || s.issuer == "" {
		problem(w, http.StatusNotFound, "not-found", "this installation has not set MATURA_PUBLIC_URL and MATURA_ISSUER")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Matura API",
		"resource_documentation":   "https://github.com/marunsct/Platform/blob/main/docs/guide/agents.md",
	})
}

// bearerChallenge is the WWW-Authenticate value of a 401 for a missing or invalid bearer token; it points clients
// at the resource metadata when maturad knows its public URL.
func (s *Server) bearerChallenge() string {
	if s.resource == "" {
		return `Bearer realm="matura"`
	}
	return `Bearer realm="matura", resource_metadata="` + ResourceMetadataURL(s.resource) + `"`
}
