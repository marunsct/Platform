package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// IdentityProvider is a Keycloak identity provider (broker) in the realm.
type IdentityProvider struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName,omitempty"`
	ProviderID                string            `json:"providerId"` // oidc or saml
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail"`
	HideOnLogin               bool              `json:"hideOnLogin"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias  string            `json:"postBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string `json:"config"`
}

// IdentityProviderMapper maps something the identity provider asserts onto the Keycloak user.
type IdentityProviderMapper struct {
	ID                     string            `json:"id,omitempty"`
	Name                   string            `json:"name"`
	IdentityProviderAlias  string            `json:"identityProviderAlias"`
	IdentityProviderMapper string            `json:"identityProviderMapper"`
	Config                 map[string]string `json:"config"`
}

func idpPath(alias string) string { return "identity-provider/instances/" + url.PathEscape(alias) }

// ImportConfig has Keycloak read an OIDC discovery document or SAML metadata at fromURL and returns the
// identity-provider configuration it found (endpoints, certificates, NameID format…).
func (c *Client) ImportConfig(ctx context.Context, providerID, fromURL string) (map[string]string, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodPost, "identity-provider/import-config",
		map[string]string{"providerId": providerID, "fromUrl": fromURL}, &out); err != nil {
		return nil, err
	}
	cfg := make(map[string]string, len(out))
	for k, v := range out {
		if s, ok := v.(string); ok {
			cfg[k] = s
		}
	}
	return cfg, nil
}

// CreateIdentityProvider adds an identity provider; ErrConflict when the alias is taken.
func (c *Client) CreateIdentityProvider(ctx context.Context, idp IdentityProvider) error {
	return c.do(ctx, http.MethodPost, "identity-provider/instances", idp, nil)
}

// UpdateIdentityProvider replaces an identity provider's settings.
func (c *Client) UpdateIdentityProvider(ctx context.Context, idp IdentityProvider) error {
	return c.do(ctx, http.MethodPut, idpPath(idp.Alias), idp, nil)
}

// IdentityProvider reads one identity provider by alias.
func (c *Client) IdentityProvider(ctx context.Context, alias string) (IdentityProvider, error) {
	var out IdentityProvider
	err := c.do(ctx, http.MethodGet, idpPath(alias), nil, &out)
	return out, err
}

// DeleteIdentityProvider removes an identity provider and its mappers and links; a missing one is not an error.
func (c *Client) DeleteIdentityProvider(ctx context.Context, alias string) error {
	if err := c.do(ctx, http.MethodDelete, idpPath(alias), nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// IdentityProviderMappers lists an identity provider's mappers.
func (c *Client) IdentityProviderMappers(ctx context.Context, alias string) ([]IdentityProviderMapper, error) {
	var out []IdentityProviderMapper
	err := c.do(ctx, http.MethodGet, idpPath(alias)+"/mappers", nil, &out)
	return out, err
}

// AddIdentityProviderMapper adds a mapper to an identity provider.
func (c *Client) AddIdentityProviderMapper(ctx context.Context, m IdentityProviderMapper) error {
	return c.do(ctx, http.MethodPost, idpPath(m.IdentityProviderAlias)+"/mappers", m, nil)
}

// PutIdentityProvider creates the identity provider with its mappers, or brings an existing one with the same
// alias back to exactly this definition (its mappers are replaced).
func (c *Client) PutIdentityProvider(ctx context.Context, idp IdentityProvider, mappers []IdentityProviderMapper) error {
	err := c.CreateIdentityProvider(ctx, idp)
	if errors.Is(err, ErrConflict) {
		if err = c.UpdateIdentityProvider(ctx, idp); err == nil {
			var old []IdentityProviderMapper
			if old, err = c.IdentityProviderMappers(ctx, idp.Alias); err == nil {
				for _, m := range old {
					if err = c.do(ctx, http.MethodDelete, idpPath(idp.Alias)+"/mappers/"+url.PathEscape(m.ID),
						nil, nil); err != nil && !isNotFound(err) {
						return err
					}
				}
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}
	for _, m := range mappers {
		m.IdentityProviderAlias = idp.Alias
		if err := c.AddIdentityProviderMapper(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
