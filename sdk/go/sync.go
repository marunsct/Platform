package matura

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// SnapshotEvents turns a snapshot into events the contract applies with the same version rule (no event ids, so not
// de-duplicated).
func SnapshotEvents(s *Snapshot) []*Event {
	var out []*Event
	add := func(obj, typ string, raw json.RawMessage) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			return
		}
		var v struct {
			Version int64 `json:"version"`
		}
		_ = json.Unmarshal(raw, &v)
		out = append(out, &Event{Type: "matura." + typ, Data: EventData{Object: obj, Version: v.Version, Payload: raw}})
	}
	for _, r := range s.Roles {
		add("app_role", "app.role.updated", r)
	}
	add("tenant", "tenant.updated", s.Tenant)
	for _, w := range s.Workspaces {
		add("workspace", "workspace.updated", w)
	}
	for _, u := range s.Users {
		add("user", "user.updated", u)
	}
	for _, m := range s.Memberships {
		add("membership", "membership.updated", m)
	}
	for _, g := range s.Grants {
		add("grant", "grant.added", g)
	}
	add("placement", "placement.updated", s.Placement)
	return out
}

// Sync keeps the contract tables current from the change feed: Bootstrap once, then CatchUp at start-up and hourly.
// Each page is applied and its cursor stored in one transaction, so a crash repeats at most one page. DB connects as
// a role that may write every tenant's rows (the owner role in shared mode).
type Sync struct {
	Client   *Client
	App      string // the app's slug (its client id), as in /v1/apps/{app}/changes
	Contract *Contract
	DB       TxBeginner
	Stream   string // matura_sync_cursor.stream (default "changes")
	Limit    int    // page size (default 500)
	// Revocations, when set, get each matura.revocation.created event the feed carries.
	Revocations *Revocations
}

func (s *Sync) applyAll(ctx context.Context, events []*Event) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		for _, e := range events {
			if s.Revocations != nil {
				s.Revocations.Apply(e)
			}
			if _, err := s.Contract.Apply(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// Bootstrap snapshots every tenant that enabled the app, then stores the cursor the first snapshot gave.
func (s *Sync) Bootstrap(ctx context.Context) (string, error) {
	index, err := s.Client.Snapshot(ctx, s.App, "")
	if err != nil {
		return "", err
	}
	if err := s.applyAll(ctx, SnapshotEvents(index)); err != nil {
		return "", err
	}
	for _, tid := range index.Tenants {
		snap, err := s.Client.Snapshot(ctx, s.App, tid)
		if err != nil {
			return "", err
		}
		if err := s.applyAll(ctx, SnapshotEvents(snap)); err != nil {
			return "", err
		}
	}
	cursor := string(index.Cursor)
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error { return s.Contract.SaveCursor(ctx, tx, cursor, s.Stream) })
	return cursor, err
}

// CatchUp applies every change after the stored cursor (bootstrapping first when there is none, or when it expired)
// and returns how many events were new. maxPages 0 means 1000.
func (s *Sync) CatchUp(ctx context.Context, maxPages int) (int, error) {
	if maxPages <= 0 {
		maxPages = 1000
	}
	var cursor string
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) (err error) {
		cursor, err = s.Contract.Cursor(ctx, tx, s.Stream)
		return err
	})
	if err != nil {
		return 0, err
	}
	if cursor == "" {
		if cursor, err = s.Bootstrap(ctx); err != nil {
			return 0, err
		}
	}
	applied := 0
	for range maxPages {
		page, err := s.Client.Changes(ctx, s.App, cursor, s.Limit)
		if errors.Is(err, ErrCursorExpired) {
			if cursor, err = s.Bootstrap(ctx); err != nil {
				return applied, err
			}
			continue
		}
		if err != nil {
			return applied, err
		}
		n := 0
		err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			for _, e := range page.Items {
				if e == nil {
					continue
				}
				ok, err := s.Contract.Apply(ctx, tx, e)
				if err != nil {
					return err
				}
				if ok {
					n++
				}
			}
			return s.Contract.SaveCursor(ctx, tx, page.NextCursor, s.Stream)
		})
		if err != nil {
			return applied, err
		}
		applied += n
		cursor = page.NextCursor
		if !page.HasMore {
			break
		}
	}
	return applied, nil
}
