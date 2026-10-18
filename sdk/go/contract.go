package matura

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ContractVersion is the version of the matura_* tables this SDK writes.
const ContractVersion = "matura.contract.v1"

// ErrInvalidEvent: the event lacks a field the contract needs (answer 400; nothing was written).
var ErrInvalidEvent = errors.New("invalid event")

// Executor runs SQL: a pgx.Tx, *pgx.Conn, *pgxpool.Pool or *pgxpool.Conn. Run Apply inside a transaction so the inbox
// row, the upserts and the hooks commit together.
type Executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Statement is one SQL statement with its positional arguments.
type Statement struct {
	SQL  string
	Args []any
}

// Hook runs after an event is applied, in the same transaction; an error rolls the transaction back.
type Hook func(ctx context.Context, db Executor, e *Event) error

// Contract applies Matura changes to the contract tables (PostgreSQL) with the version rule, and runs the app's hooks.
//
// Every change, from a webhook, the change feed, a snapshot or a token, goes through Apply, which keeps a row only
// when its version is newer than the stored one. Order and duplicates therefore do not matter.
type Contract struct {
	mu    sync.RWMutex
	hooks map[string][]Hook
}

// NewContract returns a contract with no hooks.
func NewContract() *Contract {
	return &Contract{hooks: map[string][]Hook{}}
}

// On registers a hook for an object ("membership"), an exact event type ("matura.placement.provisioned") or every
// event ("*").
func (c *Contract) On(key string, h Hook) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hooks[key] = append(c.hooks[key], h)
}

// Create creates the contract tables (idempotent) and records the contract version. rls adds the shared-mode
// row-level security policies.
func (c *Contract) Create(ctx context.Context, db Executor, rls bool) error {
	for _, stmt := range DDL(rls) {
		if _, err := db.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

type col struct {
	name string
	val  any
}

func placeholders(n int) string {
	p := make([]string, n)
	for i := range p {
		p[i] = fmt.Sprintf("$%d", i+1)
	}
	return strings.Join(p, ", ")
}

func split(cols []col) ([]string, []any) {
	names := make([]string, len(cols))
	args := make([]any, len(cols))
	for i, c := range cols {
		names[i], args[i] = c.name, c.val
	}
	return names, args
}

// keepPlacedMode: once a placement is applied, data_mode is the placement's (it has its own version), not the
// tenant's default.
var keepPlacedMode = map[string]string{
	"data_mode": "CASE WHEN t.placement_version > 0 THEN t.data_mode ELSE excluded.data_mode END",
}

func upsert(table string, key []string, cols []col, override map[string]string) Statement {
	names, args := split(cols)
	var sets []string
	for _, n := range names {
		if !containsStr(key, n) {
			v, ok := override[n]
			if !ok {
				v = "excluded." + n
			}
			sets = append(sets, n+" = "+v)
		}
	}
	return Statement{fmt.Sprintf("INSERT INTO %s AS t (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s "+
		"WHERE t.version < excluded.version", table, strings.Join(names, ", "), placeholders(len(names)),
		strings.Join(key, ", "), strings.Join(sets, ", ")), args}
}

func placeholder(table string, cols []col, key string) Statement {
	names, args := split(cols)
	return Statement{fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING", table,
		strings.Join(names, ", "), placeholders(len(names)), key), args}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$`)

// payload reads an event's object with the contract's rules for missing and malformed fields.
type payload struct {
	obj string
	m   map[string]any
	err error
}

func (p *payload) fail(format string, a ...any) {
	if p.err == nil {
		p.err = fmt.Errorf("%w: %s", ErrInvalidEvent, fmt.Sprintf(format, a...))
	}
}

func (p *payload) req(key string) any {
	v := p.m[key]
	if v == nil {
		p.fail("the %s in this event has no %s", p.obj, key)
	}
	return v
}

func (p *payload) str(key string) string { return str(p.req(key)) }

func (p *payload) opt(key string) any {
	if v := p.m[key]; v != nil {
		return str(v)
	}
	return nil
}

func (p *payload) or(key, def string) string {
	if v := str(p.m[key]); v != "" {
		return v
	}
	return def
}

func (p *payload) id(v any) any {
	s := str(v)
	if s == "" {
		return nil
	}
	if !uuidRe.MatchString(s) {
		p.fail("not a UUID: %s", s)
	}
	return s
}

func (p *payload) reqID(key string) any { return p.id(p.req(key)) }

func (p *payload) ts(key string) time.Time {
	s := str(p.m[key])
	if s == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		p.fail("not a timestamp: %s", s)
	}
	return t
}

func (p *payload) truth(key string) bool { return p.m[key] == true }

func tenantStub(tid any) Statement {
	s := str(tid)
	return placeholder("matura_tenant", []col{{"id", tid}, {"slug", s}, {"name", s}, {"kind", "company"},
		{"status", "active"}, {"plan", nil}, {"data_mode", "shared"}, {"version", 0}, {"updated_at", time.Now().UTC()}}, "id")
}

func userStub(uid any) Statement {
	return placeholder("matura_user", []col{{"id", uid}, {"email", nil}, {"email_verified", false},
		{"display_name", nil}, {"locale", nil}, {"kind", "human"}, {"status", "active"}, {"version", 0},
		{"updated_at", time.Now().UTC()}}, "id")
}

// Statements returns the SQL that applies one event. Errors wrap ErrInvalidEvent.
func (c *Contract) Statements(e *Event) ([]Statement, error) {
	obj, version := e.Data.Object, e.Data.Version
	var m map[string]any
	if obj == "" || json.Unmarshal(e.Data.Payload, &m) != nil || m == nil {
		return nil, nil
	}
	p := &payload{obj: obj, m: m}
	now := time.Now().UTC()
	var out []Statement
	switch obj {
	case "tenant":
		out = []Statement{upsert("matura_tenant", []string{"id"}, []col{
			{"id", p.reqID("id")}, {"slug", p.str("slug")}, {"name", p.str("name")}, {"kind", p.or("kind", "company")},
			{"status", p.str("status")}, {"plan", p.opt("plan")},
			{"data_mode", p.or("data_mode", p.or("data_mode_default", "shared"))},
			{"version", version}, {"updated_at", p.ts("updated_at")}}, keepPlacedMode)}
	case "workspace":
		tid := p.reqID("tenant_id")
		out = []Statement{tenantStub(tid), upsert("matura_workspace", []string{"id"}, []col{
			{"id", p.reqID("id")}, {"tenant_id", tid}, {"name", p.str("name")}, {"status", p.str("status")},
			{"is_default", p.truth("is_default")}, {"version", version}, {"updated_at", p.ts("updated_at")}}, nil)}
	case "user":
		out = []Statement{upsert("matura_user", []string{"id"}, []col{
			{"id", p.reqID("id")}, {"email", p.opt("email")}, {"email_verified", p.truth("email_verified")},
			{"display_name", p.opt("display_name")}, {"locale", p.opt("locale")}, {"kind", p.or("kind", "human")},
			{"status", p.str("status")}, {"version", version}, {"updated_at", p.ts("updated_at")}}, nil)}
	case "membership":
		tid, uid := p.reqID("tenant_id"), p.reqID("user_id")
		out = []Statement{tenantStub(tid), userStub(uid), upsert("matura_membership", []string{"tenant_id", "user_id"}, []col{
			{"tenant_id", tid}, {"user_id", uid}, {"tenant_role", p.str("tenant_role")}, {"status", p.str("status")},
			{"joined_at", p.ts("joined_at")}, {"version", version}, {"updated_at", p.ts("updated_at")}}, nil)}
	case "grant":
		tid, wid := p.reqID("tenant_id"), p.id(m["workspace_id"])
		out = []Statement{tenantStub(tid)}
		if wid != nil {
			out = append(out, placeholder("matura_workspace", []col{{"id", wid}, {"tenant_id", tid},
				{"name", str(wid)}, {"status", "active"}, {"is_default", false}, {"version", 0}, {"updated_at", now}}, "id"))
		}
		out = append(out, upsert("matura_role_grant", []string{"id"}, []col{
			{"id", p.reqID("id")}, {"tenant_id", tid}, {"workspace_id", wid}, {"subject_type", p.str("subject_type")},
			{"subject_id", p.reqID("subject_id")}, {"role", p.str("role")}, {"status", p.str("status")},
			{"version", version}, {"updated_at", p.ts("updated_at")}}, nil))
	case "app_role":
		role := p
		if nested, ok := m["role"].(map[string]any); ok {
			role = &payload{obj: obj, m: nested}
		}
		name := role.str("name")
		if role != p && role.err != nil {
			p.fail("the app_role in this event has no name")
		}
		if prev := str(m["previous_name"]); prev != "" {
			// renamed in Matura: grants follow, as they do there
			out = append(out, Statement{"UPDATE matura_role_grant SET role = $1 WHERE role = $2", []any{name, prev}})
			// the old name is gone as of this version, even if its creation arrives later
			out = append(out, upsert("matura_app_role", []string{"name"}, []col{{"name", prev}, {"description", nil},
				{"permissions", []string{}}, {"is_default", false}, {"status", "deleted"}, {"version", version},
				{"updated_at", now}}, nil))
		}
		status := "active"
		if strings.HasSuffix(e.Type, ".deleted") {
			status = "deleted"
		}
		out = append(out, upsert("matura_app_role", []string{"name"}, []col{{"name", name},
			{"description", role.opt("description")}, {"permissions", strs(role.m["permissions"])},
			{"is_default", role.truth("is_default")}, {"status", status}, {"version", version}, {"updated_at", now}}, nil))
	case "placement":
		// versioned on its own: matura_tenant.placement_version
		tid := p.reqID("tenant_id")
		out = []Statement{tenantStub(tid), {"UPDATE matura_tenant SET data_mode = $1, placement_version = $2 " +
			"WHERE id = $3 AND placement_version < $2", []any{p.str("mode"), version, tid}}}
	default:
		return nil, nil // tenant_app, app_manifest, ping: hooks only
	}
	if p.err != nil {
		return nil, p.err
	}
	return out, nil
}

// FromPrincipal returns the rows a verified token can create (just-in-time, contract §5). They are written only when
// missing, with version 0, so the next event or feed read (always a higher version) fills in what a token lacks.
func (c *Contract) FromPrincipal(pr *Principal) []Statement {
	if pr.TenantID == "" {
		return nil
	}
	now := time.Now().UTC()
	slug := pr.TenantSlug
	if slug == "" {
		slug = pr.TenantID
	}
	mode := pr.PlacementMode
	if mode == "" {
		mode = "shared"
	}
	kind := pr.Kind
	if kind == "" {
		kind = "human"
		if pr.IsService {
			kind = "service"
		}
	}
	var email, name any
	if pr.Email != "" {
		email = pr.Email
	}
	if pr.Name != "" {
		name = pr.Name
	}
	role := "member"
	if len(pr.TenantRoles) > 0 {
		role = pr.TenantRoles[0]
	}
	return []Statement{
		placeholder("matura_tenant", []col{{"id", pr.TenantID}, {"slug", slug}, {"name", slug}, {"kind", "company"},
			{"status", "active"}, {"plan", nil}, {"data_mode", mode}, {"version", 0}, {"updated_at", now}}, "id"),
		placeholder("matura_user", []col{{"id", pr.UserID}, {"email", email}, {"email_verified", pr.EmailVerified},
			{"display_name", name}, {"locale", nil}, {"kind", kind}, {"status", "active"}, {"version", 0},
			{"updated_at", now}}, "id"),
		placeholder("matura_membership", []col{{"tenant_id", pr.TenantID}, {"user_id", pr.UserID},
			{"tenant_role", role}, {"status", "active"}, {"joined_at", now}, {"version", 0}, {"updated_at", now}},
			"tenant_id, user_id"),
	}
}

// Apply applies one event and runs its hooks, in the caller's transaction. It returns false for an event id already
// applied (matura_inbox); events without an id (snapshots) are not de-duplicated. An event that lacks a needed field
// returns an error wrapping ErrInvalidEvent before anything is written.
func (c *Contract) Apply(ctx context.Context, db Executor, e *Event) (bool, error) {
	stmts, err := c.Statements(e)
	if err != nil {
		return false, err
	}
	if e.ID != "" {
		tag, err := db.Exec(ctx, `INSERT INTO matura_inbox (event_id, received_at) VALUES ($1, now())
			ON CONFLICT (event_id) DO NOTHING`, e.ID)
		if err != nil {
			return false, err
		}
		if tag.RowsAffected() == 0 {
			return false, nil
		}
	}
	for _, s := range stmts {
		if _, err := db.Exec(ctx, s.SQL, s.Args...); err != nil {
			return false, err
		}
	}
	c.mu.RLock()
	hooks := append(append(append([]Hook{}, c.hooks[e.Data.Object]...), c.hooks[e.Type]...), c.hooks["*"]...)
	c.mu.RUnlock()
	for _, h := range hooks {
		if err := h(ctx, db, e); err != nil {
			return false, err
		}
	}
	return true, nil
}

// ApplyPrincipal writes the just-in-time rows for a verified token (see FromPrincipal).
func (c *Contract) ApplyPrincipal(ctx context.Context, db Executor, p *Principal) error {
	for _, s := range c.FromPrincipal(p) {
		if _, err := db.Exec(ctx, s.SQL, s.Args...); err != nil {
			return err
		}
	}
	return nil
}

// Cursor returns the stored change-feed cursor of a stream ("changes" by default), or "" before the first sync.
func (c *Contract) Cursor(ctx context.Context, db Executor, stream string) (string, error) {
	var cur string
	err := db.QueryRow(ctx, `SELECT cursor FROM matura_sync_cursor WHERE stream = $1`, streamOr(stream)).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return cur, err
}

// SaveCursor stores the change-feed cursor of a stream ("changes" by default).
func (c *Contract) SaveCursor(ctx context.Context, db Executor, cursor, stream string) error {
	_, err := db.Exec(ctx, `INSERT INTO matura_sync_cursor (stream, cursor, synced_at) VALUES ($1, $2, now())
		ON CONFLICT (stream) DO UPDATE SET cursor = excluded.cursor, synced_at = excluded.synced_at`,
		streamOr(stream), cursor)
	return err
}

// PruneInbox forgets processed event ids older than olderThan (default 7 days); the feed and the version rule cover
// anything older.
func (c *Contract) PruneInbox(ctx context.Context, db Executor, olderThan time.Duration) error {
	if olderThan <= 0 {
		olderThan = 7 * 24 * time.Hour
	}
	_, err := db.Exec(ctx, `DELETE FROM matura_inbox WHERE received_at < $1`, time.Now().Add(-olderThan))
	return err
}

func streamOr(s string) string {
	if s == "" {
		return "changes"
	}
	return s
}
