package access

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/store"
)

const syncLock = 7351009

// Syncer mirrors Matura's facts into OpenFGA: tenant roles from memberships, workspaces' tenants, and app role
// grants. It reads the outbox from its own cursor and applies each change before moving the cursor, so a crash
// repeats changes (writes ignore duplicates and missing tuples) and never skips one. Every maturad replica runs
// one; an advisory lock makes exactly one of them active.
type Syncer struct {
	Service  *Service
	Interval time.Duration // between rounds; default 1 s
	Batch    int           // outbox rows per round; default 500
}

// Run loops until ctx ends, taking over when the active replica goes away.
func (s *Syncer) Run(ctx context.Context) {
	for ctx.Err() == nil {
		release, ok, err := s.Service.Store.TryLeader(ctx, syncLock)
		if err != nil && ctx.Err() == nil {
			s.Service.log().Warn("permissions sync: leader check failed", "err", err)
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

func (s *Syncer) lead(ctx context.Context) {
	interval := s.Interval
	if interval == 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := s.Round(ctx); err != nil && ctx.Err() == nil {
			s.Service.log().Warn("permissions sync round failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Round applies the outbox changes after the cursor, or writes every current fact when there is no cursor (first
// run, a new store, or a cursor older than the outbox keeps). Tests call it directly.
func (s *Syncer) Round(ctx context.Context) error {
	if _, _, err := s.Service.Ready(ctx); err != nil {
		return s.Service.Checked(ctx, err)
	}
	st, err := s.Service.Store.FGAState(ctx)
	if err != nil {
		return err
	}
	if st.Cursor == nil {
		return s.resync(ctx)
	}
	batch := s.Batch
	if batch == 0 {
		batch = 500
	}
	changes, err := s.Service.Store.OutboxAfter(ctx, *st.Cursor, batch)
	if errors.Is(err, store.ErrGone) {
		return s.resync(ctx)
	}
	if err != nil {
		return err
	}
	cursor := *st.Cursor
	defer func() {
		if cursor != *st.Cursor {
			if err := s.Service.Store.SetFGACursor(context.WithoutCancel(ctx), &cursor); err != nil {
				s.Service.log().Warn("permissions sync: saving cursor failed", "err", err)
			}
		}
	}()
	for _, c := range changes {
		if err := s.apply(ctx, c); err != nil {
			return s.Service.Checked(ctx, err)
		}
		cursor = c.Seq
	}
	return nil
}

// resync writes every current fact, then continues from the outbox position they were read at. Tuples of facts
// that ended while no cursor was kept stay until their next change (doc: technical specification §18).
func (s *Syncer) resync(ctx context.Context) error {
	storeID, base, err := s.Service.Ready(ctx)
	if err != nil {
		return err
	}
	facts, err := s.Service.Store.FGAFacts(ctx)
	if err != nil {
		return err
	}
	var writes []fga.TupleKey
	for _, m := range facts.Members {
		writes = append(writes, memberTuple(m))
	}
	for _, w := range facts.Workspaces {
		writes = append(writes, workspaceTuple(w))
	}
	for _, g := range facts.Grants {
		writes = append(writes, grantTuple(g, g.Role))
	}
	for _, g := range facts.Groups {
		writes = append(writes, groupTuple(g))
	}
	for len(writes) > 0 {
		n := min(len(writes), fga.MaxWrite)
		if err := s.Service.Client.Write(ctx, storeID, base, writes[:n], nil); err != nil {
			return s.Service.Checked(ctx, err)
		}
		writes = writes[n:]
	}
	apps, err := s.Service.Store.ListApps(ctx)
	if err != nil {
		return err
	}
	for _, a := range apps {
		s.writeModel(ctx, a)
	}
	s.Service.log().Info("permissions synced in full", "members", len(facts.Members),
		"workspaces", len(facts.Workspaces), "grants", len(facts.Grants))
	return s.Service.Store.SetFGACursor(ctx, &facts.Cursor)
}

func (s *Syncer) writeModel(ctx context.Context, a store.App) {
	_, _, _, err := s.Service.AppModel(ctx, a)
	var fe *fga.Error
	switch {
	case err == nil, errors.Is(err, ErrNoModel):
	case errors.As(err, &fe) && fe.Invalid():
		// OpenFGA refused the model: the app's checks answer with this error until its manifest is fixed
		s.Service.log().Warn("OpenFGA refused the app's authorization model", "app", a.Slug, "err", err)
	default:
		s.Service.log().Warn("writing the app's authorization model failed", "app", a.Slug, "err", err)
	}
}

func memberTuple(m store.Membership) fga.TupleKey {
	return fga.TupleKey{User: fga.UserSubject(m.TenantID, m.UserID), Relation: m.TenantRole,
		Object: fga.TenantObject(m.TenantID)}
}

func workspaceTuple(w store.Workspace) fga.TupleKey {
	return fga.TupleKey{User: fga.TenantObject(w.TenantID), Relation: "tenant", Object: fga.WorkspaceObject(w.TenantID, w.ID)}
}

func groupTuple(g store.SCIMGroupMember) fga.TupleKey {
	return fga.TupleKey{User: fga.UserSubject(g.TenantID, g.UserID), Relation: "member",
		Object: fga.GroupObject(g.TenantID, g.GroupID)}
}

func grantTuple(g store.Grant, role string) fga.TupleKey {
	user := fga.UserSubject(g.TenantID, g.SubjectID)
	if g.SubjectType == "group" {
		user = fga.GroupMembers(g.TenantID, g.SubjectID)
	}
	return fga.TupleKey{User: user, Relation: "assignee", Object: fga.RoleObject(g.TenantID, g.AppSlug, role, g.WorkspaceID)}
}

// apply turns one outbox change into tuple writes and deletes.
func (s *Syncer) apply(ctx context.Context, c store.Change) error {
	storeID, base, err := s.Service.Ready(ctx)
	if err != nil {
		return err
	}
	var writes, deletes []fga.TupleKey
	switch {
	case strings.HasPrefix(c.Type, "matura.membership."):
		var m store.Membership
		if err := json.Unmarshal(c.Payload, &m); err != nil {
			return err
		}
		for _, r := range fga.TenantRoles {
			k := memberTuple(m)
			k.Relation = r
			if m.Status == "active" && r == m.TenantRole {
				writes = append(writes, k)
			} else {
				deletes = append(deletes, k)
			}
		}
	case strings.HasPrefix(c.Type, "matura.workspace."):
		var w store.Workspace
		if err := json.Unmarshal(c.Payload, &w); err != nil {
			return err
		}
		if w.Status == "deleted" {
			deletes = append(deletes, workspaceTuple(w))
		} else {
			writes = append(writes, workspaceTuple(w))
		}
	case c.Type == "matura.grant.added" || c.Type == "matura.grant.revoked":
		var g store.Grant
		if err := json.Unmarshal(c.Payload, &g); err != nil {
			return err
		}
		if g.Status == "active" {
			writes = append(writes, grantTuple(g, g.Role))
		} else {
			deletes = append(deletes, grantTuple(g, g.Role))
		}
	case c.Type == "matura.scim_group.member_added" || c.Type == "matura.scim_group.member_removed":
		var g store.SCIMGroupMember
		if err := json.Unmarshal(c.Payload, &g); err != nil {
			return err
		}
		if c.Type == "matura.scim_group.member_added" {
			writes = append(writes, groupTuple(g))
		} else {
			deletes = append(deletes, groupTuple(g))
		}
	case c.Type == "matura.app.role.updated":
		return s.renameRole(ctx, storeID, base, c)
	case c.Type == "matura.app.manifest.updated":
		var a store.App
		if err := json.Unmarshal(c.Payload, &a); err != nil {
			return err
		}
		s.writeModel(ctx, a)
		return nil
	case c.Type == "matura.tenant.deleting" && c.TenantID != nil:
		return s.purgeTenant(ctx, storeID, base, *c.TenantID)
	default:
		return nil
	}
	return s.Service.Client.Write(ctx, storeID, base, writes, deletes)
}

// renameRole moves grants' tuples to a role's new name (grants follow a rename in the database without events).
func (s *Syncer) renameRole(ctx context.Context, storeID, base string, c store.Change) error {
	var p struct {
		Previous string `json:"previous_name"`
		Role     struct {
			Name string `json:"name"`
		} `json:"role"`
	}
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		return err
	}
	slug, _, _ := strings.Cut(strings.TrimPrefix(c.Subject, "apps/"), "/")
	if p.Previous == "" || p.Previous == p.Role.Name {
		return nil
	}
	app, err := s.Service.Store.GetApp(ctx, slug)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	grants, err := s.Service.Store.AppGrants(ctx, app.ID)
	if err != nil {
		return err
	}
	var writes, deletes []fga.TupleKey
	flush := func() error {
		err := s.Service.Client.Write(ctx, storeID, base, writes, deletes)
		writes, deletes = nil, nil
		return err
	}
	for _, g := range grants {
		if g.Role != p.Role.Name {
			continue
		}
		deletes = append(deletes, grantTuple(g, p.Previous))
		writes = append(writes, grantTuple(g, g.Role))
		if len(writes)+len(deletes) >= fga.MaxWrite {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// purgeTenant deletes every tuple of a deleted tenant: its own facts and whatever its apps wrote. OpenFGA cannot
// read by id prefix, so this reads the whole store once.
func (s *Syncer) purgeTenant(ctx context.Context, storeID, base string, tid uuid.UUID) error {
	var mine []fga.TupleKey
	token := ""
	for {
		page, next, err := s.Service.Client.Read(ctx, storeID, nil, token)
		if err != nil {
			return err
		}
		for _, k := range page {
			if fga.InTenant(k.Object, tid) {
				mine = append(mine, k)
			}
		}
		if next == "" {
			break
		}
		token = next
	}
	for len(mine) > 0 {
		n := min(len(mine), fga.MaxWrite)
		// deletes are not checked against a model's types, so the base model serves for apps' tuples too
		if err := s.Service.Client.Write(ctx, storeID, base, nil, mine[:n]); err != nil {
			return err
		}
		mine = mine[n:]
	}
	s.Service.log().Info("permissions of a deleted tenant removed", "tenant", tid)
	return nil
}
