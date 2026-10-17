package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// Session is one of a user's Keycloak SSO sessions (a browser or device that signed in).
type Session struct {
	ID         string
	UserID     string
	IPAddress  string
	Started    time.Time
	LastAccess time.Time
	RememberMe bool
	Clients    []string // client ids of the apps used in the session, sorted
}

type sessionRep struct {
	ID         string            `json:"id"`
	UserID     string            `json:"userId"`
	IPAddress  string            `json:"ipAddress"`
	Start      int64             `json:"start"`
	LastAccess int64             `json:"lastAccess"`
	RememberMe bool              `json:"rememberMe"`
	Clients    map[string]string `json:"clients"`
}

// UserSessions lists the user's active SSO sessions, most recently used first.
func (c *Client) UserSessions(ctx context.Context, userID string) ([]Session, error) {
	var reps []sessionRep
	if err := c.do(ctx, http.MethodGet, "users/"+url.PathEscape(userID)+"/sessions", nil, &reps); err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(reps))
	for _, r := range reps {
		s := Session{ID: r.ID, UserID: r.UserID, IPAddress: r.IPAddress, Started: time.UnixMilli(r.Start).UTC(),
			LastAccess: time.UnixMilli(r.LastAccess).UTC(), RememberMe: r.RememberMe, Clients: []string{}}
		for _, clientID := range r.Clients {
			s.Clients = append(s.Clients, clientID)
		}
		sort.Strings(s.Clients)
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastAccess.After(out[j].LastAccess) })
	return out, nil
}

// DeleteSession ends one SSO session; its refresh tokens stop working. Callers check the session is the user's.
func (c *Client) DeleteSession(ctx context.Context, sessionID string) error {
	return c.do(ctx, http.MethodDelete, "sessions/"+url.PathEscape(sessionID), nil, nil)
}

// LogoutUser ends every session of the user, sending back-channel logout to clients that asked for it.
func (c *Client) LogoutUser(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodPost, "users/"+url.PathEscape(userID)+"/logout", nil, nil)
}

// Credential types Keycloak uses for second factors.
const (
	CredentialPassword     = "password"
	CredentialOTP          = "otp"
	CredentialWebAuthn     = "webauthn"              // security key or passkey as second factor
	CredentialPasskey      = "webauthn-passwordless" // passkey sign-in
	CredentialRecoveryCode = "recovery-authn-codes"
)

// IsSecondFactor says whether a credential type counts as multi-factor.
func IsSecondFactor(typ string) bool {
	switch typ {
	case CredentialOTP, CredentialWebAuthn, CredentialPasskey, CredentialRecoveryCode:
		return true
	}
	return false
}

// Credential is a stored credential's metadata; secrets never leave Keycloak.
type Credential struct {
	ID      string
	Type    string
	Label   string
	Created time.Time
}

// Credentials lists the user's credentials.
func (c *Client) Credentials(ctx context.Context, userID string) ([]Credential, error) {
	var reps []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		UserLabel   string `json:"userLabel"`
		CreatedDate int64  `json:"createdDate"`
	}
	if err := c.do(ctx, http.MethodGet, "users/"+url.PathEscape(userID)+"/credentials", nil, &reps); err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(reps))
	for _, r := range reps {
		out = append(out, Credential{ID: r.ID, Type: r.Type, Label: r.UserLabel,
			Created: time.UnixMilli(r.CreatedDate).UTC()})
	}
	return out, nil
}

// DeleteCredential removes one credential of the user.
func (c *Client) DeleteCredential(ctx context.Context, userID, credentialID string) error {
	return c.do(ctx, http.MethodDelete,
		"users/"+url.PathEscape(userID)+"/credentials/"+url.PathEscape(credentialID), nil, nil)
}

// ResetSecondFactors removes every OTP, WebAuthn, passkey and recovery-code credential of the user and ends their
// sessions. It returns how many credentials it removed.
func (c *Client) ResetSecondFactors(ctx context.Context, userID string) (int, error) {
	creds, err := c.Credentials(ctx, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, cr := range creds {
		if !IsSecondFactor(cr.Type) {
			continue
		}
		if err := c.DeleteCredential(ctx, userID, cr.ID); err != nil && !isNotFound(err) {
			return n, err
		}
		n++
	}
	return n, c.LogoutUser(ctx, userID)
}
