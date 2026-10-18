package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// MapperID is the provider id of Matura's token mapper (keycloak/extensions).
const MapperID = "matura-token-mapper"

// AgentClient describes the confidential client of a tenant service account or AI agent (TS15).
type AgentClient struct {
	ClientID    string // e.g. agent-3f9c2a1b7d4e
	Name        string
	Description string
	TenantID    string // kept as client attributes, for people reading the Keycloak admin console
	Kind        string // service or agent
}

// CreatedClient is what Keycloak assigned to a new agent client. Secret is shown to the caller once.
type CreatedClient struct {
	UUID          string // Keycloak's internal id of the client
	ServiceUserID string // the service-account user: the token's sub
	Secret        string
}

func clientPath(uuid string) string { return "clients/" + url.PathEscape(uuid) }

// CreateAgentClient creates a confidential client with only the client-credentials grant and standard token
// exchange (RFC 8693) enabled, the Matura token mapper attached, and no realm roles in its tokens. It returns the
// client's internal id, its service-account user and its secret. ErrConflict when the client id is taken.
func (c *Client) CreateAgentClient(ctx context.Context, a AgentClient) (CreatedClient, error) {
	rep := map[string]any{
		"clientId": a.ClientID, "name": a.Name, "description": a.Description, "enabled": true,
		"protocol": "openid-connect", "publicClient": false, "clientAuthenticatorType": "client-secret",
		"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
		"implicitFlowEnabled": false, "frontchannelLogout": false, "fullScopeAllowed": false,
		"attributes": map[string]string{
			"standard.token.exchange.enabled": "true",
			"matura.tenant_id":                a.TenantID,
			"matura.kind":                     a.Kind,
		},
		"protocolMappers": []map[string]any{{"name": "matura tenant and permissions", "protocol": "openid-connect",
			"protocolMapper": MapperID, "config": map[string]string{}}},
	}
	if err := c.do(ctx, http.MethodPost, "clients", rep, nil); err != nil {
		return CreatedClient{}, err
	}
	var out CreatedClient
	var err error
	if out.UUID, err = c.clientUUID(ctx, a.ClientID); err != nil {
		return out, err
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, clientPath(out.UUID)+"/service-account-user", nil, &user); err != nil {
		return out, err
	}
	if user.ID == "" {
		return out, fmt.Errorf("keycloak: client %s has no service-account user", a.ClientID)
	}
	out.ServiceUserID = user.ID
	out.Secret, err = c.clientSecret(ctx, out.UUID, http.MethodGet)
	return out, err
}

func (c *Client) clientUUID(ctx context.Context, clientID string) (string, error) {
	var list []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	if err := c.do(ctx, http.MethodGet, "clients?clientId="+url.QueryEscape(clientID), nil, &list); err != nil {
		return "", err
	}
	for _, x := range list {
		if x.ClientID == clientID {
			return x.ID, nil
		}
	}
	return "", &Error{Op: "GET clients?clientId", Status: http.StatusNotFound, Body: "client " + clientID + " not found"}
}

func (c *Client) clientSecret(ctx context.Context, uuid, method string) (string, error) {
	var sec struct {
		Value string `json:"value"`
	}
	if err := c.do(ctx, method, clientPath(uuid)+"/client-secret", nil, &sec); err != nil {
		return "", err
	}
	if sec.Value == "" {
		return "", fmt.Errorf("keycloak: client has no secret")
	}
	return sec.Value, nil
}

// RotateClientSecret generates a new secret for the client; the old one stops working at once.
func (c *Client) RotateClientSecret(ctx context.Context, uuid string) (string, error) {
	return c.clientSecret(ctx, uuid, http.MethodPost)
}

// UpdateAgentClient changes the client's name, description and whether it is enabled. A disabled client gets no
// tokens, by client credentials or token exchange.
func (c *Client) UpdateAgentClient(ctx context.Context, uuid string, a AgentClient, enabled bool) error {
	return c.do(ctx, http.MethodPut, clientPath(uuid), map[string]any{"clientId": a.ClientID, "name": a.Name,
		"description": a.Description, "enabled": enabled}, nil)
}

// DeleteClient removes a client and its service-account user. A client that is already gone is not an error.
func (c *Client) DeleteClient(ctx context.Context, uuid string) error {
	if err := c.do(ctx, http.MethodDelete, clientPath(uuid), nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}
