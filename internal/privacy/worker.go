// Package privacy runs maturad's data-protection background work (TS17, technical specification §14): it builds
// tenant export bundles, clears expired ones, and purges audit events past each tenant's retention.
package privacy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/marunsct/Platform/internal/store"
)

const lockKey = 7351008

// Worker runs on every maturad replica; an advisory lock makes exactly one of them active.
type Worker struct {
	Store       *store.Store
	Log         *slog.Logger
	Interval    time.Duration // between export rounds; default 2 s
	PurgeEvery  time.Duration // between retention runs; default 1 h
	lastPurgeAt time.Time
}

func (w *Worker) defaults() {
	if w.Interval == 0 {
		w.Interval = 2 * time.Second
	}
	if w.PurgeEvery == 0 {
		w.PurgeEvery = time.Hour
	}
	if w.Log == nil {
		w.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (w *Worker) Run(ctx context.Context) {
	w.defaults()
	for ctx.Err() == nil {
		release, ok, err := w.Store.TryLeader(ctx, lockKey)
		if err != nil && ctx.Err() == nil {
			w.Log.Warn("privacy worker: leader check failed", "err", err)
		}
		if ok {
			w.lead(ctx)
			release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func (w *Worker) lead(ctx context.Context) {
	tick := time.NewTicker(w.Interval)
	defer tick.Stop()
	for {
		if err := w.Exports(ctx); err != nil && ctx.Err() == nil {
			w.Log.Warn("privacy worker: export round failed", "err", err)
		}
		if time.Since(w.lastPurgeAt) >= w.PurgeEvery {
			if _, err := w.Purge(ctx); err != nil && ctx.Err() == nil {
				w.Log.Warn("privacy worker: retention run failed", "err", err)
			}
			w.lastPurgeAt = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Exports builds every queued export and clears expired bundles.
func (w *Worker) Exports(ctx context.Context) error {
	w.defaults()
	for ctx.Err() == nil {
		e, err := w.Store.ClaimExport(ctx)
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			return err
		}
		bundle, err := w.Store.BuildTenantBundle(ctx, e.TenantID, e.ID)
		if err != nil {
			w.Log.Error("tenant export failed", "tenant", e.TenantID, "export", e.ID, "err", err)
			if _, ferr := w.Store.FailExport(ctx, e, "the export could not be built; try again or ask your operator"); ferr != nil {
				return ferr
			}
			continue
		}
		if _, err := w.Store.FinishExport(ctx, e, bundle); err != nil {
			return err
		}
	}
	_, err := w.Store.ExpireExports(ctx)
	return err
}

// Purge applies every tenant's audit retention and returns what it removed.
func (w *Worker) Purge(ctx context.Context) ([]store.Purge, error) {
	w.defaults()
	tenants, err := w.Store.AuditTenants(ctx)
	if err != nil {
		return nil, err
	}
	var out []store.Purge
	for _, tid := range tenants {
		p, err := w.Store.PurgeAudit(ctx, tid)
		if err != nil {
			w.Log.Error("audit retention failed", "tenant", tid, "err", err)
			continue
		}
		if p.Purged > 0 {
			w.Log.Info("audit retention purged events", "tenant", tid, "purged", p.Purged, "anchor_seq", p.AnchorSeq)
			out = append(out, p)
		}
	}
	return out, ctx.Err()
}
