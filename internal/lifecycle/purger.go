// Package lifecycle runs the tenant purger (TS10): tenants whose deletion grace period is over are deleted, and
// tenants whose apps have deleted all their data are marked deleted.
package lifecycle

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/marunsct/Platform/internal/store"
)

const purgerLock = 7351007

// Purger moves tenants pending deletion to deleting once purge_after has passed (apps get tenant.deleting and the
// placements retire, so the provisioner drops platform-managed storage once each app confirms), and deleting
// tenants to deleted once every placement is deleted. Every maturad replica runs one; an advisory lock makes
// exactly one of them active.
type Purger struct {
	Store    *store.Store
	Log      *slog.Logger
	Interval time.Duration // between rounds; default 1 minute
}

func (p *Purger) defaults() {
	if p.Interval == 0 {
		p.Interval = time.Minute
	}
	if p.Log == nil {
		p.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (p *Purger) Run(ctx context.Context) {
	p.defaults()
	for ctx.Err() == nil {
		release, ok, err := p.Store.TryLeader(ctx, purgerLock)
		if err != nil && ctx.Err() == nil {
			p.Log.Warn("purger: leader check failed", "err", err)
		}
		if ok {
			for ctx.Err() == nil {
				if _, _, err := p.Round(ctx); err != nil && ctx.Err() == nil {
					p.Log.Warn("purger round failed", "err", err)
				}
				select {
				case <-ctx.Done():
				case <-time.After(p.Interval):
				}
			}
			release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// Round purges the tenants that are due and finishes those whose data is gone; tests call it directly.
func (p *Purger) Round(ctx context.Context) (purged, finished int, err error) {
	p.defaults()
	if purged, err = p.Store.PurgeDueTenants(ctx); err != nil {
		return purged, 0, err
	}
	if purged > 0 {
		p.Log.Info("tenants purged after their grace period", "count", purged)
	}
	if finished, err = p.Store.FinishDeletedTenants(ctx); err != nil {
		return purged, finished, err
	}
	// access reviews past their deadline are completed (un-decided items revoked unless the review keeps them)
	if n, err := p.Store.CompleteDueAccessReviews(ctx); err != nil {
		return purged, finished, err
	} else if n > 0 {
		p.Log.Info("access reviews completed at their deadline", "count", n)
	}
	return purged, finished, nil
}
