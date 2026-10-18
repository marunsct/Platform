package matura

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// OAuth 2.0 Protected Resource Metadata (RFC 9728) for an app's API or MCP server (TS15). An app that exposes an MCP
// server, or any API agents call, serves this document at /.well-known/oauth-protected-resource and points 401
// answers at it, so clients find the Keycloak realm that issues tokens for it. See docs/guide/agents.md.

// WellKnownResource is the path RFC 9728 registers for protected-resource metadata.
const WellKnownResource = "/.well-known/oauth-protected-resource"

// MetadataURL is where RFC 9728 §3.1 puts a resource's metadata: the well-known path between the host and the
// resource's path.
func MetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("resource %q is not an absolute URL", resource)
	}
	return u.Scheme + "://" + u.Host + WellKnownResource + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// ResourceMetadata is the metadata document. Resource is the app's identifier (its MCP server URL, also listed in
// the manifest's auth.resources); AuthorizationServers holds the Matura realm's issuer URL.
type ResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// NewResourceMetadata returns the document for resource, with bearer tokens in the Authorization header.
func NewResourceMetadata(resource string, authorizationServers ...string) (ResourceMetadata, error) {
	if len(authorizationServers) == 0 {
		return ResourceMetadata{}, errors.New("name at least one authorization server (the Matura realm's issuer URL)")
	}
	if _, err := MetadataURL(resource); err != nil {
		return ResourceMetadata{}, err
	}
	return ResourceMetadata{Resource: resource, AuthorizationServers: authorizationServers,
		BearerMethodsSupported: []string{"header"}}, nil
}

// Challenge holds the optional parameters of a WWW-Authenticate challenge (RFC 6750 §3).
type Challenge struct {
	Realm            string
	Error            string // e.g. invalid_token, insufficient_scope
	ErrorDescription string
	Scope            string
}

func quoteParam(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// WWWAuthenticate is the WWW-Authenticate value of a 401 (or a 403 with insufficient_scope) that points the client
// at the resource's metadata (RFC 9728 §5.1).
func WWWAuthenticate(resource string, c Challenge) (string, error) {
	md, err := MetadataURL(resource)
	if err != nil {
		return "", err
	}
	var params []string
	if c.Realm != "" {
		params = append(params, "realm="+quoteParam(c.Realm))
	}
	params = append(params, "resource_metadata="+quoteParam(md))
	if c.Error != "" {
		params = append(params, "error="+quoteParam(c.Error))
	}
	if c.ErrorDescription != "" {
		params = append(params, "error_description="+quoteParam(c.ErrorDescription))
	}
	if c.Scope != "" {
		params = append(params, "scope="+quoteParam(c.Scope))
	}
	return "Bearer " + strings.Join(params, ", "), nil
}
