package matura

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrCursorExpired: the stored cursor is older than the feed keeps (30 days); take a snapshot (Sync.Bootstrap).
var ErrCursorExpired = errors.New("matura: change-feed cursor expired")

// APIError is an error status from maturad (other than 410 on the change feed).
type APIError struct {
	Status int
	Detail string
	Body   []byte
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("matura: HTTP %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("matura: HTTP %d", e.Status)
}

// Client calls maturad's app endpoints with the app's client id and secret (HTTP Basic): the change feed, snapshots
// and data placement.
type Client struct {
	BaseURL      string // maturad, e.g. https://id.example.com
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client // default: a client with a 10s timeout
}

// NewClient returns a client for maturad at baseURL.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{BaseURL: baseURL, ClientID: clientID, ClientSecret: clientSecret,
		HTTPClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, gone bool) error {
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var p struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(raw, &p)
		if resp.StatusCode == http.StatusGone && gone {
			return fmt.Errorf("%w: %s", ErrCursorExpired, p.Detail)
		}
		return &APIError{Status: resp.StatusCode, Detail: p.Detail, Body: raw}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func seg(s string) string { return url.PathEscape(s) }

// ChangesPage is one page of the change feed.
type ChangesPage struct {
	Items      []*Event `json:"items"`
	NextCursor string   `json:"next_cursor"`
	HasMore    bool     `json:"has_more"`
}

// Changes returns the changes after cursor (an opaque value from NextCursor; "" for the start), in commit order. An
// expired cursor returns an error wrapping ErrCursorExpired. limit 0 means 500.
func (c *Client) Changes(ctx context.Context, app, cursor string, limit int) (*ChangesPage, error) {
	if limit <= 0 {
		limit = 500
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	var page ChangesPage
	if err := c.do(ctx, http.MethodGet, "/v1/apps/"+seg(app)+"/changes", q, nil, &page, true); err != nil {
		return nil, err
	}
	return &page, nil
}

// Cursor is an opaque change-feed position; maturad may send it as a number or a string.
type Cursor string

func (c *Cursor) UnmarshalJSON(b []byte) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	if v == nil {
		*c = ""
	} else {
		*c = Cursor(fmt.Sprint(v))
	}
	return nil
}

// Snapshot is the current state for bootstrap. Without a tenant it is the index: Cursor, Roles and the Tenants that
// enabled the app; with a tenant, that tenant's directory and placement.
type Snapshot struct {
	Cursor      Cursor            `json:"cursor"`
	Tenant      json.RawMessage   `json:"tenant,omitempty"`
	Workspaces  []json.RawMessage `json:"workspaces,omitempty"`
	Users       []json.RawMessage `json:"users,omitempty"`
	Memberships []json.RawMessage `json:"memberships,omitempty"`
	Grants      []json.RawMessage `json:"grants,omitempty"`
	Placement   json.RawMessage   `json:"placement,omitempty"`
	Roles       []json.RawMessage `json:"roles,omitempty"`
	Tenants     []string          `json:"tenants,omitempty"`
}

// Snapshot returns the index (tenant "") or one tenant's state.
func (c *Client) Snapshot(ctx context.Context, app, tenant string) (*Snapshot, error) {
	var q url.Values
	if tenant != "" {
		q = url.Values{"tenant": {tenant}}
	}
	var s Snapshot
	if err := c.do(ctx, http.MethodGet, "/v1/apps/"+seg(app)+"/snapshot", q, nil, &s, false); err != nil {
		return nil, err
	}
	return &s, nil
}

// Placement is where a tenant's data lives for the app (technical specification §7).
type Placement struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	AppID         string `json:"app_id"`
	Mode          string `json:"mode"`    // shared, schema or database
	Manager       string `json:"manager"` // platform or app
	DBServerID    string `json:"db_server_id,omitempty"`
	DatabaseName  string `json:"database_name,omitempty"`
	SchemaName    string `json:"schema_name,omitempty"`
	LocationLabel string `json:"location_label,omitempty"`
	State         string `json:"state"` // requested, provisioned, ready, moving, retiring, deleted
	Error         string `json:"error,omitempty"`
	Version       int64  `json:"version"`
}

// Credentials connect to platform-managed storage. Keep them in memory only and ask again after ExpiresAt.
type Credentials struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	SSLMode    string    `json:"sslmode"`
	Database   string    `json:"database"`
	User       string    `json:"user"`
	Password   string    `json:"password"`
	SearchPath string    `json:"search_path,omitempty"`
	Mode       string    `json:"mode"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// StorageRegistration is storage the app created itself (placement manager "app").
type StorageRegistration struct {
	LocationLabel string `json:"location_label"`
	DatabaseName  string `json:"database_name,omitempty"`
	SchemaName    string `json:"schema_name,omitempty"`
}

// Credential purposes: Runtime for serving requests, Migrate for the role that owns the tables.
const (
	PurposeRuntime = "runtime"
	PurposeMigrate = "migrate"
)

func placementPath(app, tenant string) string {
	return "/v1/apps/" + seg(app) + "/placements/" + seg(tenant)
}

func (c *Client) placementCall(ctx context.Context, method, path string, body any) (*Placement, error) {
	var p Placement
	if err := c.do(ctx, method, path, nil, body, &p, false); err != nil {
		return nil, err
	}
	return &p, nil
}

// Placement returns where the tenant's data lives: mode, manager and state.
func (c *Client) Placement(ctx context.Context, app, tenant string) (*Placement, error) {
	return c.placementCall(ctx, http.MethodGet, placementPath(app, tenant), nil)
}

// RegisterPlacement records storage the app created itself; the placement becomes provisioned.
func (c *Client) RegisterPlacement(ctx context.Context, app, tenant string, s StorageRegistration) (*Placement, error) {
	return c.placementCall(ctx, http.MethodPut, placementPath(app, tenant), s)
}

// Credentials returns a connection for platform-managed storage. PurposeMigrate returns the role that owns the tables
// (different from the runtime role in shared mode).
func (c *Client) Credentials(ctx context.Context, app, tenant, purpose string) (*Credentials, error) {
	if purpose == "" {
		purpose = PurposeRuntime
	}
	var cr Credentials
	err := c.do(ctx, http.MethodPost, placementPath(app, tenant)+"/credentials", nil,
		map[string]string{"purpose": purpose}, &cr, false)
	if err != nil {
		return nil, err
	}
	return &cr, nil
}

// PlacementReady tells Matura the app migrated the tenant's storage and serves it.
func (c *Client) PlacementReady(ctx context.Context, app, tenant string) (*Placement, error) {
	return c.placementCall(ctx, http.MethodPost, placementPath(app, tenant)+":ready", nil)
}

// PlacementDeleted tells Matura the app deleted a retiring tenant's data; Matura then drops platform-managed storage.
func (c *Client) PlacementDeleted(ctx context.Context, app, tenant string) (*Placement, error) {
	return c.placementCall(ctx, http.MethodPost, placementPath(app, tenant)+":deleted", nil)
}
