// Package fga is a small client for OpenFGA's HTTP API and the rules that map Matura apps and tenants onto one
// OpenFGA store (ADR 0005, technical specification §18). It does not import the store: internal/access wires it up.
package fga

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
	"time"
)

// MaxWrite is the most tuples OpenFGA accepts in one write (writes and deletes together, its default limit).
const MaxWrite = 100

// MaxBatchCheck is the most checks OpenFGA accepts in one batch check (its default limit).
const MaxBatchCheck = 50

// Client calls one OpenFGA server.
type Client struct {
	URL   string       // e.g. http://openfga:8080
	Token string       // preshared key, sent as a bearer token; empty sends none
	HTTP  *http.Client // 10 s timeout by default
}

// Error is an answer OpenFGA refused, with its code (e.g. validation_error).
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("openfga: %s: %s", e.Code, e.Message) }

// Stale reports whether the error means a store or model id Matura remembered no longer exists (the OpenFGA
// server was replaced or its memory datastore restarted).
func (e *Error) Stale() bool {
	switch e.Code {
	case "store_id_not_found", "authorization_model_not_found", "latest_authorization_model_not_found":
		return true
	}
	return e.Status == http.StatusNotFound
}

// Invalid reports whether OpenFGA refused the request's content (a type, relation or tuple the model lacks).
func (e *Error) Invalid() bool {
	return e.Status == http.StatusBadRequest && !e.Stale()
}

// TupleKey is one relationship: user has relation on object.
type TupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("openfga unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		e := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(raw, e)
		if e.Code == "" {
			e.Code = http.StatusText(resp.StatusCode)
		}
		return e
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

var defaultHTTP = &http.Client{Timeout: 10 * time.Second}

// UnmarshalJSON reads OpenFGA's error body ({"code": ..., "message": ...}).
func (e *Error) UnmarshalJSON(b []byte) error {
	var v struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	e.Code, e.Message = v.Code, v.Message
	return nil
}

// FindStore returns the id of the oldest store with this name, or "" when there is none.
func (c *Client) FindStore(ctx context.Context, name string) (string, error) {
	token, best, bestAt := "", "", ""
	for {
		var out struct {
			Stores []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				CreatedAt string `json:"created_at"`
			} `json:"stores"`
			ContinuationToken string `json:"continuation_token"`
		}
		q := url.Values{"page_size": {"100"}}
		if token != "" {
			q.Set("continuation_token", token)
		}
		if err := c.do(ctx, http.MethodGet, "/stores?"+q.Encode(), nil, &out); err != nil {
			return "", err
		}
		for _, s := range out.Stores {
			if s.Name == name && (best == "" || s.CreatedAt < bestAt) {
				best, bestAt = s.ID, s.CreatedAt
			}
		}
		if out.ContinuationToken == "" || len(out.Stores) == 0 {
			return best, nil
		}
		token = out.ContinuationToken
	}
}

// StoreExists reports whether the store is still there.
func (c *Client) StoreExists(ctx context.Context, id string) (bool, error) {
	err := c.do(ctx, http.MethodGet, "/stores/"+url.PathEscape(id), nil, nil)
	var e *Error
	if errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Code == "store_id_not_found") {
		return false, nil
	}
	return err == nil, err
}

// CreateStore creates a store and returns its id.
func (c *Client) CreateStore(ctx context.Context, name string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/stores", map[string]string{"name": name}, &out)
	return out.ID, err
}

// WriteModel stores an authorisation model and returns its id. Models are immutable: each write is a new id.
func (c *Client) WriteModel(ctx context.Context, store string, m Model) (string, error) {
	var out struct {
		ID string `json:"authorization_model_id"`
	}
	err := c.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(store)+"/authorization-models", m, &out)
	return out.ID, err
}

// Write adds and removes tuples in one transaction. Adding a tuple that exists and removing one that does not are
// not errors, so a write can be repeated (at-least-once delivery).
func (c *Client) Write(ctx context.Context, store, model string, writes, deletes []TupleKey) error {
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	body := map[string]any{"authorization_model_id": model}
	if len(writes) > 0 {
		body["writes"] = map[string]any{"tuple_keys": writes, "on_duplicate": "ignore"}
	}
	if len(deletes) > 0 {
		body["deletes"] = map[string]any{"tuple_keys": deletes, "on_missing": "ignore"}
	}
	return c.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(store)+"/write", body, nil)
}

// Read returns one page of the store's tuples (every tuple when key is nil) and the token for the next page
// ("" at the end).
func (c *Client) Read(ctx context.Context, store string, key *TupleKey, token string) ([]TupleKey, string, error) {
	body := map[string]any{"page_size": 100}
	if key != nil {
		body["tuple_key"] = key
	}
	if token != "" {
		body["continuation_token"] = token
	}
	var out struct {
		Tuples []struct {
			Key TupleKey `json:"key"`
		} `json:"tuples"`
		ContinuationToken string `json:"continuation_token"`
	}
	if err := c.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(store)+"/read", body, &out); err != nil {
		return nil, "", err
	}
	keys := make([]TupleKey, len(out.Tuples))
	for i, t := range out.Tuples {
		keys[i] = t.Key
	}
	return keys, out.ContinuationToken, nil
}

// Query is what Check, BatchCheck and ListObjects share.
type Query struct {
	Model      string
	Contextual []TupleKey
	Higher     bool // HIGHER_CONSISTENCY: skip OpenFGA's cache, for a check right after a write
}

func (q Query) body() map[string]any {
	b := map[string]any{"authorization_model_id": q.Model}
	if len(q.Contextual) > 0 {
		b["contextual_tuples"] = map[string]any{"tuple_keys": q.Contextual}
	}
	if q.Higher {
		b["consistency"] = "HIGHER_CONSISTENCY"
	}
	return b
}

// Check answers whether key holds.
func (c *Client) Check(ctx context.Context, store string, q Query, key TupleKey) (bool, error) {
	body := q.body()
	body["tuple_key"] = key
	var out struct {
		Allowed bool `json:"allowed"`
	}
	err := c.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(store)+"/check", body, &out)
	return out.Allowed, err
}

// CheckResult is one answer of a batch check; Error is set when that check could not be evaluated.
type CheckResult struct {
	Allowed bool
	Error   string
}

// BatchCheck answers several checks (at most MaxBatchCheck), in the order given. Contextual tuples in q apply to
// every check.
func (c *Client) BatchCheck(ctx context.Context, store string, q Query, keys []TupleKey) ([]CheckResult, error) {
	body := q.body()
	delete(body, "contextual_tuples")
	checks := make([]map[string]any, len(keys))
	for i, k := range keys {
		checks[i] = map[string]any{"tuple_key": k, "correlation_id": fmt.Sprint(i)}
		if len(q.Contextual) > 0 {
			checks[i]["contextual_tuples"] = map[string]any{"tuple_keys": q.Contextual}
		}
	}
	body["checks"] = checks
	var out struct {
		Result map[string]struct {
			Allowed bool `json:"allowed"`
			Error   *struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(store)+"/batch-check", body, &out); err != nil {
		return nil, err
	}
	res := make([]CheckResult, len(keys))
	for i := range keys {
		r, ok := out.Result[fmt.Sprint(i)]
		switch {
		case !ok:
			res[i].Error = "no answer"
		case r.Error != nil:
			res[i].Error = r.Error.Message
		default:
			res[i].Allowed = r.Allowed
		}
	}
	return res, nil
}

// ListObjects returns the objects of type the user has relation on (OpenFGA caps the answer, 1000 by default).
func (c *Client) ListObjects(ctx context.Context, store string, q Query, user, relation, typ string) ([]string, error) {
	body := q.body()
	body["user"], body["relation"], body["type"] = user, relation, typ
	var out struct {
		Objects []string `json:"objects"`
	}
	err := c.do(ctx, http.MethodPost, "/stores/"+url.PathEscape(store)+"/list-objects", body, &out)
	return out.Objects, err
}
