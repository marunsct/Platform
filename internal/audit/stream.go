// Package audit streams tenants' audit logs to the destinations they configure (TS9, technical specification §13).
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/marunsct/Platform/internal/events"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
)

const streamLock = 7351006

// Streamer delivers each destination's new audit events in chain order, a batch per request, signed like
// webhooks. Every maturad replica runs one; an advisory lock makes exactly one of them active.
type Streamer struct {
	Store    *store.Store
	Keys     secrets.KeyManager
	Client   *http.Client // 10 s timeout by default
	Log      *slog.Logger
	Interval time.Duration // between rounds; default 1 s
	Batch    int           // events per request; default 100
}

func (s *Streamer) defaults() {
	if s.Client == nil {
		s.Client = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if s.Interval == 0 {
		s.Interval = time.Second
	}
	if s.Batch == 0 {
		s.Batch = 100
	}
	if s.Log == nil {
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (s *Streamer) Run(ctx context.Context) {
	s.defaults()
	for ctx.Err() == nil {
		release, ok, err := s.Store.TryLeader(ctx, streamLock)
		if err != nil && ctx.Err() == nil {
			s.Log.Warn("audit stream: leader check failed", "err", err)
		}
		if ok {
			s.lead(ctx)
			release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *Streamer) lead(ctx context.Context) {
	tick := time.NewTicker(s.Interval)
	defer tick.Stop()
	for {
		if err := s.Round(ctx); err != nil && ctx.Err() == nil {
			s.Log.Warn("audit stream round failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Round makes one delivery pass over due destinations. Tests call it directly.
func (s *Streamer) Round(ctx context.Context) error {
	s.defaults()
	due, err := s.Store.DueAuditSinks(ctx, s.Keys, 50)
	if err != nil {
		return err
	}
	for _, d := range due {
		if err := s.deliver(ctx, d); err != nil {
			s.Log.Warn("audit stream bookkeeping failed", "sink", d.ID, "err", err)
		}
	}
	return nil
}

func (s *Streamer) deliver(ctx context.Context, d store.DueAuditSink) error {
	evs, err := s.Store.AuditChain(ctx, store.Scope{Operator: true}, d.TenantID, d.Cursor, s.Batch, nil, nil)
	if err != nil || len(evs) == 0 {
		return err
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	first, last := evs[0].Seq, evs[len(evs)-1].Seq
	status, err := s.post(ctx, d, first, last, body.Bytes())
	if err != nil {
		s.Log.Info("audit delivery failed", "sink", d.ID, "status", status, "err", err)
		return s.Store.AuditSinkFailed(ctx, d.ID, status, err.Error())
	}
	return s.Store.AuditSinkDelivered(ctx, d.ID, last, len(evs))
}

// post sends one batch as NDJSON. Any 2xx acknowledges it; redirects are not followed.
func (s *Streamer) post(ctx context.Context, d store.DueAuditSink, first, last int64, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("User-Agent", "matura-audit/1")
	req.Header.Set("Matura-Audit-Sink", d.ID.String())
	req.Header.Set("Matura-Audit-Tenant", d.TenantID.String())
	req.Header.Set("Matura-Audit-Seq", strconv.FormatInt(first, 10)+"-"+strconv.FormatInt(last, 10))
	req.Header.Set("Matura-Signature", events.Sign(d.Key, time.Now(), body))
	res, err := s.Client.Do(req)
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
