// Package keycloak is maturad's client for Keycloak's admin REST API, for one realm (technical specification §5.3).
//
// It signs in with the client-credentials grant of a confidential client whose service account holds only the
// realm-management roles it needs (view-users, manage-users, view-identity-providers, manage-identity-providers;
// the `matura-admin` client in keycloak/realm/matura-realm.json). The access token is cached until shortly before
// it expires and fetched again once when Keycloak answers 401.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound is a 404 from Keycloak: no such user, session, credential or identity provider.
	ErrNotFound = errors.New("keycloak: not found")
	// ErrConflict is a 409 from Keycloak, e.g. an identity provider alias that is taken.
	ErrConflict = errors.New("keycloak: conflict")
	// ErrUnavailable means Keycloak could not be reached or did not answer in time.
	ErrUnavailable = errors.New("keycloak: unavailable")
	// ErrForbidden means the service account lacks a role for the call (check the matura-admin client).
	ErrForbidden = errors.New("keycloak: the service account is not allowed to do this")
)

// Error is a refusal from Keycloak. It matches ErrNotFound, ErrConflict and ErrForbidden with errors.Is.
type Error struct {
	Op     string // what maturad tried, e.g. "GET users/{id}/sessions"
	Status int
	Body   string // Keycloak's error message, shortened
}

func (e *Error) Error() string {
	return fmt.Sprintf("keycloak: %s: %d %s", e.Op, e.Status, e.Body)
}

func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrConflict:
		return e.Status == http.StatusConflict
	case ErrForbidden:
		return e.Status == http.StatusForbidden
	}
	return false
}

// Config says which Keycloak and realm to manage and how to sign in.
type Config struct {
	BaseURL      string // e.g. http://keycloak:8180 (no /realms/...)
	Realm        string
	ClientID     string
	ClientSecret string
	Timeout      time.Duration // per request; default 10 s
	HTTP         *http.Client  // optional
}

// Client calls the admin API of one realm. It is safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New checks the configuration and returns a client. It does not contact Keycloak.
func New(cfg Config) (*Client, error) {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if _, err := url.ParseRequestURI(cfg.BaseURL); err != nil || cfg.BaseURL == "" {
		return nil, fmt.Errorf("keycloak: base URL %q is not a URL", cfg.BaseURL)
	}
	if cfg.Realm == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("keycloak: realm, client id and client secret are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{cfg: cfg, http: hc}, nil
}

// Realm is the realm this client manages.
func (c *Client) Realm() string { return c.cfg.Realm }

// SplitIssuer turns a realm issuer URL (https://id.example.com/realms/matura) into its base URL and realm name.
func SplitIssuer(issuer string) (base, realm string, err error) {
	u, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("issuer %q is not a URL", issuer)
	}
	i := strings.LastIndex(u.Path, "/realms/")
	if i < 0 || u.Path[i+len("/realms/"):] == "" || strings.Contains(u.Path[i+len("/realms/"):], "/") {
		return "", "", fmt.Errorf("issuer %q does not end in /realms/<name>", issuer)
	}
	realm, err = url.PathUnescape(u.Path[i+len("/realms/"):])
	if err != nil {
		return "", "", err
	}
	u.Path = u.Path[:i]
	u.RawPath = ""
	return u.String(), realm, nil
}

// accessToken returns a cached token, or signs in again when it expires within 30 seconds (or force is set).
func (c *Client) accessToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Until(c.expires) > 30*time.Second {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret}}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.BaseURL+"/realms/"+url.PathEscape(c.cfg.Realm)+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return "", &Error{Op: "client-credentials sign-in", Status: res.StatusCode, Body: short(body)}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("keycloak: token response without access_token")
	}
	c.token, c.expires = tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second)
	return c.token, nil
}

// do calls the admin API at path (relative to /admin/realms/{realm}/), sending in as JSON and decoding the answer
// into out when both are non-nil. A 401 signs in again once.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	_, err := c.send(ctx, method, path, in, out)
	return err
}

// send is do that also returns the response headers (Location of a created resource).
func (c *Client) send(ctx context.Context, method, path string, in, out any) (http.Header, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	op := method + " " + path
	for attempt := 0; ; attempt++ {
		token, err := c.accessToken(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		rctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
		req, err := http.NewRequestWithContext(rctx, method,
			c.cfg.BaseURL+"/admin/realms/"+url.PathEscape(c.cfg.Realm)+"/"+path, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.http.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, op, err)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, op, err)
		}
		if res.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if res.StatusCode >= 300 {
			return nil, &Error{Op: op, Status: res.StatusCode, Body: short(raw)}
		}
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return nil, fmt.Errorf("keycloak: %s: unexpected answer: %w", op, err)
			}
		}
		return res.Header, nil
	}
}

// short keeps Keycloak's error message readable in logs.
func short(b []byte) string {
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorMessage     string `json:"errorMessage"`
	}
	if json.Unmarshal(b, &e) == nil {
		for _, s := range []string{e.ErrorMessage, e.ErrorDescription, e.Error} {
			if s != "" {
				return s
			}
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
