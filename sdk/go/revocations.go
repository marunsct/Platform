package matura

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Revocation stops tokens issued at or before NotBefore (technical specification §21): those whose sub, or act.sub,
// is UserID (when ActorID is set: whose sub is UserID and act.sub is ActorID); for TenantID only when it is set; for
// SessionID only when it is set.
type Revocation struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	ActorID   string    `json:"actor_id"` // only tokens this agent got for UserID (a consent withdrawn)
	SessionID string    `json:"session_id"`
	NotBefore time.Time `json:"not_before"`
	Reason    string    `json:"reason"`
}

// Covers says whether the revocation stops a token with these claims.
func (r Revocation) Covers(c *Claims) bool {
	if c == nil || c.IssuedAt == 0 {
		return false
	}
	if r.ActorID != "" {
		if r.UserID != c.Subject || c.Act == nil || c.Act.Sub != r.ActorID {
			return false
		}
	} else if r.UserID != c.Subject && (c.Act == nil || r.UserID != c.Act.Sub) {
		return false
	}
	if r.TenantID != "" && r.TenantID != c.TenantID {
		return false
	}
	if r.SessionID != "" && r.SessionID != c.SessionID {
		return false
	}
	return !time.Unix(c.IssuedAt, 0).After(r.NotBefore)
}

// RevocationWindow is how long a revocation matters (the longest token lifetime plus skew, with margin).
const RevocationWindow = 15 * time.Minute

// Revocations is the set of recent revocations a Verifier consults, so a revoked token stops being accepted as soon
// as the app hears of it instead of when it expires. Fill it at start with Load, and keep it current with Apply
// (WebhookHandler and Sync call it when their Revocations field is set) or by calling Load every few seconds. Safe
// for concurrent use.
type Revocations struct {
	mu   sync.RWMutex
	byID map[string]Revocation
	now  func() time.Time
}

// NewRevocations returns an empty set.
func NewRevocations() *Revocations {
	return &Revocations{byID: map[string]Revocation{}, now: time.Now}
}

// Add records a revocation (again: no change) and forgets ones past RevocationWindow.
func (s *Revocations) Add(rs ...Revocation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-RevocationWindow)
	for id, r := range s.byID {
		if r.NotBefore.Before(cutoff) {
			delete(s.byID, id)
		}
	}
	for _, r := range rs {
		if r.ID != "" && !r.NotBefore.Before(cutoff) {
			s.byID[r.ID] = r
		}
	}
}

// Apply adds the revocation a matura.revocation.created event carries; other events are ignored. It reports
// whether the event was a revocation.
func (s *Revocations) Apply(e *Event) bool {
	if e == nil || e.Type != "matura.revocation.created" || e.Data.Object != "revocation" {
		return false
	}
	var r Revocation
	if err := e.Decode(&r); err != nil || r.UserID == "" {
		return false
	}
	s.Add(r)
	return true
}

// Revoked says whether a revocation in the set stops a token with these claims.
func (s *Revocations) Revoked(c *Claims) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.byID {
		if r.Covers(c) {
			return true
		}
	}
	return false
}

// Len is the number of revocations held.
func (s *Revocations) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Load fetches the app's recent revocations (GET /v1/apps/{app}/revocations) and adds them.
func (s *Revocations) Load(ctx context.Context, c *Client, app string) error {
	var out struct {
		Items []Revocation `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/apps/"+seg(app)+"/revocations", nil, nil, &out, false); err != nil {
		return err
	}
	s.Add(out.Items...)
	return nil
}

// Poll calls Load every interval until ctx ends (for apps without webhooks); errors go to onError when set.
func (s *Revocations) Poll(ctx context.Context, c *Client, app string, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Load(ctx, c, app); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
