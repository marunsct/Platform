package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
)

const relayLock = 7351003

// Relay sequences the outbox, delivers webhooks in order per endpoint, and prunes rows past the feed horizon.
// Every maturad replica runs one; an advisory lock makes exactly one of them active.
type Relay struct {
	Store    *store.Store
	Keys     secrets.KeyManager
	Source   string       // CloudEvents source, e.g. matura://installation/main
	Client   *http.Client // 10 s timeout by default
	Log      *slog.Logger
	Interval time.Duration // between rounds; default 500 ms
	GiveUp   time.Duration // retry one event this long, then skip it; default 24 h
	Keep     time.Duration // outbox retention (feed horizon); default 30 days
}

func (r *Relay) defaults() {
	if r.Client == nil {
		r.Client = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if r.Interval == 0 {
		r.Interval = 500 * time.Millisecond
	}
	if r.GiveUp == 0 {
		r.GiveUp = 24 * time.Hour
	}
	if r.Keep == 0 {
		r.Keep = 30 * 24 * time.Hour
	}
	if r.Source == "" {
		r.Source = "matura://installation/main"
	}
	if r.Log == nil {
		r.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (r *Relay) Run(ctx context.Context) {
	r.defaults()
	for ctx.Err() == nil {
		release, ok, err := r.Store.TryLeader(ctx, relayLock)
		if err != nil && ctx.Err() == nil {
			r.Log.Warn("relay: leader check failed", "err", err)
		}
		if ok {
			r.lead(ctx)
			release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func (r *Relay) lead(ctx context.Context) {
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
	lastPrune := time.Time{}
	for {
		if err := r.Round(ctx); err != nil && ctx.Err() == nil {
			r.Log.Warn("relay round failed", "err", err)
		}
		if time.Since(lastPrune) > time.Hour {
			if n, err := r.Store.PruneOutbox(ctx, r.Keep); err != nil {
				r.Log.Warn("outbox prune failed", "err", err)
			} else if n > 0 {
				r.Log.Info("outbox pruned", "rows", n)
			}
			if n, err := r.Store.PruneRevocations(ctx); err != nil {
				r.Log.Warn("revocation prune failed", "err", err)
			} else if n > 0 {
				r.Log.Info("revocations pruned", "rows", n)
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Round sequences new outbox rows and makes one delivery pass over due endpoints. Tests call it directly.
func (r *Relay) Round(ctx context.Context) error {
	r.defaults()
	if _, err := r.Store.Sequence(ctx); err != nil {
		return err
	}
	due, err := r.Store.DueWebhooks(ctx, r.Keys, 50)
	if err != nil {
		return err
	}
	for _, h := range due {
		if err := r.deliver(ctx, h); err != nil {
			r.Log.Warn("webhook delivery bookkeeping failed", "endpoint", h.ID, "err", err)
		}
	}
	return nil
}

func (r *Relay) deliver(ctx context.Context, h store.DueWebhook) error {
	changes, next, err := r.Store.Changes(ctx, h.AppRef, h.Cursor, 100)
	if err != nil {
		return err
	}
	done := 0
	for _, c := range changes {
		status, err := r.post(ctx, h, FromChange(r.Source, c))
		if err != nil {
			if done > 0 {
				if err := r.Store.WebhookDelivered(ctx, h.ID, changes[done-1].Seq, done, time.Now()); err != nil {
					return err
				}
			}
			r.Log.Info("webhook delivery failed", "endpoint", h.ID, "event", c.ID, "status", status, "err", err)
			return r.Store.WebhookFailed(ctx, h.ID, c.Seq, status, err.Error(), r.GiveUp)
		}
		done++
	}
	if next == h.Cursor && done == 0 {
		return nil // nothing new; stays due and is looked at next round
	}
	return r.Store.WebhookDelivered(ctx, h.ID, next, done, time.Now())
}

// post sends one event. Any 2xx is success; redirects are not followed.
func (r *Relay) post(ctx context.Context, h store.DueWebhook, e Envelope) (int, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return 0, err
	}
	return Post(ctx, r.Client, h.URL, h.Key, e.ID, body)
}

// Post delivers a signed body to a webhook URL.
func Post(ctx context.Context, c *http.Client, url string, key []byte, eventID string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("User-Agent", "matura-webhooks/1")
	req.Header.Set("Matura-Event-Id", eventID)
	req.Header.Set("Matura-Signature", Sign(key, time.Now(), body))
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res.StatusCode, fmt.Errorf("receiver answered %d", res.StatusCode)
	}
	return res.StatusCode, nil
}
