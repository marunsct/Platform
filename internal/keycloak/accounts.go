package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Account is a user account in the realm (the fields of Keycloak's UserRepresentation maturad uses).
type Account struct {
	ID            string              `json:"id,omitempty"`
	Username      string              `json:"username,omitempty"`
	Email         string              `json:"email,omitempty"`
	EmailVerified bool                `json:"emailVerified"`
	FirstName     string              `json:"firstName,omitempty"`
	LastName      string              `json:"lastName,omitempty"`
	Enabled       bool                `json:"enabled"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	// only when creating: a password credential, and actions the person must take at first sign-in
	Credentials     []PasswordCredential `json:"credentials,omitempty"`
	RequiredActions []string             `json:"requiredActions,omitempty"`
}

// PasswordCredential is a password set on a new account; Temporary makes Keycloak ask for a new one at sign-in.
type PasswordCredential struct {
	Type      string `json:"type"` // password
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

// Attribute returns the first value of a user attribute.
func (a Account) Attribute(name string) string {
	if v := a.Attributes[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// AccountByEmail finds the account with this email address (ignoring case); ErrNotFound when there is none.
func (c *Client) AccountByEmail(ctx context.Context, email string) (Account, error) {
	var list []Account
	q := url.Values{"email": {email}, "exact": {"true"}, "briefRepresentation": {"false"}}
	if err := c.do(ctx, http.MethodGet, "users?"+q.Encode(), nil, &list); err != nil {
		return Account{}, err
	}
	for _, a := range list {
		if strings.EqualFold(a.Email, email) {
			return a, nil
		}
	}
	return Account{}, &Error{Op: "GET users?email", Status: http.StatusNotFound, Body: "no account with this email"}
}

// Account reads one account.
func (c *Client) Account(ctx context.Context, id string) (Account, error) {
	var a Account
	err := c.do(ctx, http.MethodGet, "users/"+url.PathEscape(id), nil, &a)
	return a, err
}

// CreateAccount creates an account and returns its id. ErrConflict when the username or email is taken.
func (c *Client) CreateAccount(ctx context.Context, a Account) (string, error) {
	a.ID = ""
	h, err := c.send(ctx, http.MethodPost, "users", a, nil)
	if err != nil {
		return "", err
	}
	loc := h.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("keycloak: POST users: no Location in the answer")
	}
	return path.Base(loc), nil
}

// AccountChange is a partial update of an account; nil fields stay as they are. An attribute set to "" is removed.
type AccountChange struct {
	Email      *string
	FirstName  *string
	LastName   *string
	Attributes map[string]string
}

// UpdateAccount reads the account, applies the change and writes it back, so fields maturad does not know about
// (required actions, other attributes) are kept.
func (c *Client) UpdateAccount(ctx context.Context, id string, ch AccountChange) error {
	var rep map[string]any
	if err := c.do(ctx, http.MethodGet, "users/"+url.PathEscape(id), nil, &rep); err != nil {
		return err
	}
	if ch.Email != nil {
		rep["email"] = *ch.Email
		rep["emailVerified"] = true
	}
	if ch.FirstName != nil {
		rep["firstName"] = *ch.FirstName
	}
	if ch.LastName != nil {
		rep["lastName"] = *ch.LastName
	}
	if len(ch.Attributes) > 0 {
		attrs, _ := rep["attributes"].(map[string]any)
		if attrs == nil {
			attrs = map[string]any{}
		}
		for k, v := range ch.Attributes {
			if v == "" {
				delete(attrs, k)
			} else {
				attrs[k] = []string{v}
			}
		}
		rep["attributes"] = attrs
	}
	return c.do(ctx, http.MethodPut, "users/"+url.PathEscape(id), rep, nil)
}
