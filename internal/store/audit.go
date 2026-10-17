package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Actor is who caused a change, as the audit log records it. The API puts it in the request context; work with no
// actor in its context (the provisioner, the relay) is recorded as "system".
type Actor struct {
	Kind      string // user, operator, app or system
	ID        uuid.UUID
	Email     string
	RequestID string
	IP        string
	UserAgent string
}

type actorKey struct{}

func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

func ActorFrom(ctx context.Context) Actor {
	a, _ := ctx.Value(actorKey{}).(Actor)
	if a.Kind == "" {
		a.Kind = "system"
	}
	return a
}

// AuditEvent is one record of the audit log. Hash covers every field but ID (see Canonical).
type AuditEvent struct {
	ID        int64           `json:"id"`
	TenantID  *uuid.UUID      `json:"tenant_id"`
	Seq       int64           `json:"seq"`
	Time      time.Time       `json:"time"`
	Actor     AuditActor      `json:"actor"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	RequestID string          `json:"request_id"`
	IP        string          `json:"ip"`
	UserAgent string          `json:"user_agent"`
	Data      json.RawMessage `json:"data"`
	PrevHash  string          `json:"prev_hash"` // hex
	Hash      string          `json:"hash"`      // hex
	// Redacted marks an event shown with an erased user's email or name replaced by their pseudonym (§14.3): its
	// Hash is the stored event's, so it no longer recomputes from the fields shown, but the next event still links
	// to it.
	Redacted bool `json:"redacted,omitempty"`
}

type AuditActor struct {
	Kind  string     `json:"kind"`
	ID    *uuid.UUID `json:"id"`
	Email string     `json:"email"`
}

var genesis = make([]byte, sha256.Size)

// Canonical is the byte string an event's hash is computed over: a JSON object of every field except id, hash and
// the event's own position in the response, with keys sorted, no insignificant whitespace, HTML characters not
// escaped, null strings written as "", the time in UTC with microseconds, and numbers in data written as integers
// when they are integers and in Go's shortest float form otherwise.
func (e AuditEvent) Canonical() ([]byte, error) {
	var data any
	if len(e.Data) > 0 {
		dec := json.NewDecoder(bytes.NewReader(e.Data))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil, err
		}
	}
	str := func(id *uuid.UUID) string {
		if id == nil {
			return ""
		}
		return id.String()
	}
	rec := map[string]any{
		"tenant_id":  str(e.TenantID),
		"seq":        json.Number(strconv.FormatInt(e.Seq, 10)),
		"time":       e.Time.UTC().Format("2006-01-02T15:04:05.000000Z"),
		"actor":      map[string]any{"kind": e.Actor.Kind, "id": str(e.Actor.ID), "email": e.Actor.Email},
		"action":     e.Action,
		"target":     e.Target,
		"request_id": e.RequestID,
		"ip":         e.IP,
		"user_agent": e.UserAgent,
		"data":       data,
		"prev_hash":  e.PrevHash,
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, rec); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ComputeHash returns the hex SHA-256 of the canonical form.
func (e AuditEvent) ComputeHash() (string, error) {
	c, err := e.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		var s bytes.Buffer
		enc := json.NewEncoder(&s)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(x); err != nil {
			return err
		}
		b.Write(bytes.TrimSuffix(s.Bytes(), []byte("\n")))
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			b.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return err
		}
		b.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	case []any:
		b.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, el); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unexpected %T", v)
	}
	return nil
}

// audit appends an event to the tenant's chain (uuid.Nil: the installation chain) in the caller's transaction, so
// the record commits or rolls back with the change. Locking the chain's head row orders writers.
func audit(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action, target string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if string(raw) == "null" {
		raw = []byte("{}")
	}
	a := ActorFrom(ctx)
	var prevSeq int64
	var prev []byte
	if err := tx.QueryRow(ctx, `INSERT INTO audit_chain (chain, seq, hash) VALUES ($1, 0, $2)
		ON CONFLICT (chain) DO UPDATE SET chain = EXCLUDED.chain RETURNING seq, hash`, tenantID, genesis).
		Scan(&prevSeq, &prev); err != nil {
		return err
	}
	e := AuditEvent{Seq: prevSeq + 1, Time: time.Now().UTC().Truncate(time.Microsecond),
		Actor: AuditActor{Kind: a.Kind, Email: a.Email}, Action: action, Target: target, RequestID: a.RequestID,
		IP: a.IP, UserAgent: truncate(a.UserAgent, 512), Data: raw, PrevHash: hex.EncodeToString(prev)}
	if tenantID != uuid.Nil {
		e.TenantID = &tenantID
	}
	if a.ID != uuid.Nil {
		e.Actor.ID = &a.ID
	}
	canon, err := e.Canonical()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	// data is stored as written into the hash, so a reader recomputes the same bytes
	var dataCanon bytes.Buffer
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return err
	}
	if err := writeCanonical(&dataCanon, parsed); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_event (tenant_id, seq, time, actor_kind, actor_id, actor_email,
		action, target, request_id, ip, user_agent, data, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		e.TenantID, e.Seq, e.Time, e.Actor.Kind, e.Actor.ID, nullable(e.Actor.Email), action, target,
		nullable(e.RequestID), nullable(e.IP), nullable(e.UserAgent), dataCanon.Bytes(), prev, sum[:]); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE audit_chain SET seq = $2, hash = $3 WHERE chain = $1`, tenantID, e.Seq, sum[:])
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// RecordAudit writes an event that goes with no change of its own: a refused request, an export. tenantID
// uuid.Nil records it in the installation chain.
func (s *Store) RecordAudit(ctx context.Context, sc Scope, tenantID uuid.UUID, action, target string, data any) error {
	if tenantID != uuid.Nil {
		sc = sc.InTenant(tenantID)
	}
	return s.tx(ctx, sc, func(tx pgx.Tx) error { return audit(ctx, tx, tenantID, action, target, data) })
}

const auditCols = `id, tenant_id, seq, time, actor_kind, actor_id, coalesce(actor_email, ''), action, target,
	coalesce(request_id, ''), coalesce(ip, ''), coalesce(user_agent, ''), data, prev_hash, hash`

func scanAudit(row pgx.Row) (AuditEvent, error) {
	var e AuditEvent
	var prev, hash []byte
	err := row.Scan(&e.ID, &e.TenantID, &e.Seq, &e.Time, &e.Actor.Kind, &e.Actor.ID, &e.Actor.Email, &e.Action,
		&e.Target, &e.RequestID, &e.IP, &e.UserAgent, &e.Data, &prev, &hash)
	e.Time = e.Time.UTC()
	e.PrevHash, e.Hash = hex.EncodeToString(prev), hex.EncodeToString(hash)
	return e, mapErr(err)
}

// AuditQuery filters the audit log. Tenant nil with Installation false means every event the scope can see.
type AuditQuery struct {
	Tenant       *uuid.UUID
	Installation bool   // only installation events (tenant_id NULL); operators only
	Actor        string // user or app id, or an email address
	Action       string // prefix, e.g. "membership." or "invitation.created"
	From, To     *time.Time
	Before       int64 // cursor: events with a smaller id
	Limit        int
}

// AuditLimit is the page size used for a requested limit: 100 by default, at most 1000.
func AuditLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 100
	}
	return limit
}

// ListAudit returns events newest first. The caller pages on with Before set to the last id it got.
func (s *Store) ListAudit(ctx context.Context, sc Scope, q AuditQuery) ([]AuditEvent, error) {
	where, args := q.where()
	args = append(args, AuditLimit(q.Limit))
	var out []AuditEvent
	err := s.tx(ctx, sc, func(tx pgx.Tx) error {
		red, err := loadRedactor(ctx, tx)
		if err != nil {
			return err
		}
		if _, ok := red.email(q.Actor); ok { // an erased user cannot be found by their old address
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT `+auditCols+` FROM audit_event WHERE `+where+
			` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEvent, error) { return scanAudit(r) })
		for i := range out {
			red.event(&out[i])
		}
		return err
	})
	return out, err
}

func (q AuditQuery) where() (string, []any) {
	conds := []string{"true"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if q.Tenant != nil {
		add("tenant_id = $?", *q.Tenant)
	} else if q.Installation {
		conds = append(conds, "tenant_id IS NULL")
	}
	if q.Actor != "" {
		if id, err := uuid.Parse(q.Actor); err == nil {
			add("actor_id = $?", id)
		} else {
			add("lower(actor_email) = lower($?)", q.Actor)
		}
	}
	if q.Action != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q.Action)
		add("action LIKE $? || '%'", esc)
	}
	if q.From != nil {
		add("time >= $?", *q.From)
	}
	if q.To != nil {
		add("time < $?", *q.To)
	}
	if q.Before > 0 {
		add("id < $?", q.Before)
	}
	return strings.Join(conds, " AND "), args
}

// AuditChain returns a tenant's events (uuid.Nil: installation events) with seq after `after`, oldest first, for
// export and streaming, with erased users pseudonymised. From and To narrow it by time.
func (s *Store) AuditChain(ctx context.Context, sc Scope, tenantID uuid.UUID, after int64, limit int, from, to *time.Time) ([]AuditEvent, error) {
	return s.auditChain(ctx, sc, tenantID, after, limit, from, to, true)
}

func (s *Store) auditChain(ctx context.Context, sc Scope, tenantID uuid.UUID, after int64, limit int, from, to *time.Time, redact bool) ([]AuditEvent, error) {
	var out []AuditEvent
	if tenantID != uuid.Nil {
		sc = sc.InTenant(tenantID)
	}
	err := s.tx(ctx, sc, func(tx pgx.Tx) (err error) {
		out, err = chainPage(ctx, tx, tenantID, after, limit, from, to)
		if err != nil || !redact {
			return err
		}
		red, err := loadRedactor(ctx, tx)
		for i := range out {
			red.event(&out[i])
		}
		return err
	})
	return out, err
}

func chainPage(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, after int64, limit int, from, to *time.Time) ([]AuditEvent, error) {
	rows, err := tx.Query(ctx, `SELECT `+auditCols+` FROM audit_event
		WHERE coalesce(tenant_id, '00000000-0000-0000-0000-000000000000') = $1 AND seq > $2
		AND ($4::timestamptz IS NULL OR time >= $4) AND ($5::timestamptz IS NULL OR time < $5)
		ORDER BY seq LIMIT $3`, tenantID, after, limit, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEvent, error) { return scanAudit(r) })
}

// AuditVerification is the result of recomputing a chain.
type AuditVerification struct {
	OK         bool        `json:"ok"`
	Events     int64       `json:"events"`
	AnchorSeq  int64       `json:"anchor_seq"` // events up to here were purged by retention; checking starts after
	AnchorHash string      `json:"anchor_hash"`
	HeadSeq    int64       `json:"head_seq"`
	HeadHash   string      `json:"head_hash"`
	FirstBreak *AuditBreak `json:"first_break"`
}

type AuditBreak struct {
	Seq    int64  `json:"seq"`
	ID     int64  `json:"id,omitempty"`
	Reason string `json:"reason"`
}

// VerifyAudit recomputes every hash in the chain from its anchor (the genesis, or the last event retention purged),
// checks each event links to the one before, that no position is missing, and that the chain ends at the recorded
// head. It reports the first break. It reads the stored events, never the pseudonymised ones.
func (s *Store) VerifyAudit(ctx context.Context, sc Scope, tenantID uuid.UUID) (AuditVerification, error) {
	var out AuditVerification
	var head, anchor []byte
	hsc := sc
	if tenantID != uuid.Nil {
		hsc = sc.InTenant(tenantID)
	}
	err := s.tx(ctx, hsc, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT seq, hash, anchor_seq, anchor_hash FROM audit_chain WHERE chain = $1`, tenantID).
			Scan(&out.HeadSeq, &head, &out.AnchorSeq, &anchor)
		if errors.Is(err, pgx.ErrNoRows) {
			head = genesis
			return nil
		}
		return err
	})
	if err != nil {
		return out, err
	}
	if out.AnchorSeq == 0 || len(anchor) == 0 {
		out.AnchorSeq, anchor = 0, genesis
	}
	out.HeadHash, out.AnchorHash = hex.EncodeToString(head), hex.EncodeToString(anchor)
	prev, last := out.AnchorHash, out.AnchorSeq
	brk := func(seq, id int64, reason string) {
		out.FirstBreak = &AuditBreak{Seq: seq, ID: id, Reason: reason}
	}
	for out.FirstBreak == nil && last < out.HeadSeq {
		page, err := s.auditChain(ctx, sc, tenantID, last, 1000, nil, nil, false)
		if err != nil {
			return out, err
		}
		if len(page) == 0 {
			brk(last+1, 0, "events up to the chain head are missing")
			break
		}
		for _, e := range page {
			if e.Seq > out.HeadSeq {
				break
			}
			switch h, err := e.ComputeHash(); {
			case e.Seq != last+1:
				brk(last+1, 0, fmt.Sprintf("event %d is missing", last+1))
			case e.PrevHash != prev:
				brk(e.Seq, e.ID, "prev_hash does not match the previous event's hash")
			case err != nil || h != e.Hash:
				brk(e.Seq, e.ID, "hash does not match the event's contents")
			}
			if out.FirstBreak != nil {
				break
			}
			out.Events++
			prev, last = e.Hash, e.Seq
		}
	}
	if out.FirstBreak == nil && prev != out.HeadHash {
		brk(last, 0, "the last event does not match the chain head")
	}
	out.OK = out.FirstBreak == nil
	return out, nil
}
