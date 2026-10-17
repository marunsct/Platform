package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Pseudonymising erased users in the audit log (technical specification §14.3). Hashed events are never edited;
// audit_redaction keeps, per erased user, a pseudonym and hashes of their email and name, and every reader except
// verification replaces those values on the way out.

// Pseudonym is the stable name an erased user is shown under: deleted-user-<12 hex of sha256(user id)>.
func Pseudonym(userID uuid.UUID) string {
	sum := sha256.Sum256([]byte(userID.String()))
	return "deleted-user-" + hex.EncodeToString(sum[:])[:12]
}

func valueHash(s string) [32]byte {
	return sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
}

type erased struct {
	pseudonym string
	name      *[32]byte
}

// redactor rewrites events and records that mention erased users. The zero value (nil maps) changes nothing.
type redactor struct {
	users  map[uuid.UUID]erased
	emails map[[32]byte]string
}

func loadRedactor(ctx context.Context, tx pgx.Tx) (*redactor, error) {
	rows, err := tx.Query(ctx, `SELECT user_id, pseudonym, email_hash, name_hash FROM audit_redaction`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	r := &redactor{users: map[uuid.UUID]erased{}, emails: map[[32]byte]string{}}
	for rows.Next() {
		var id uuid.UUID
		var p string
		var email, name []byte
		if err := rows.Scan(&id, &p, &email, &name); err != nil {
			return nil, err
		}
		e := erased{pseudonym: p}
		if len(name) == 32 {
			var h [32]byte
			copy(h[:], name)
			e.name = &h
		}
		r.users[id] = e
		if len(email) == 32 {
			var h [32]byte
			copy(h[:], email)
			r.emails[h] = p
		}
	}
	return r, rows.Err()
}

func (r *redactor) empty() bool { return r == nil || len(r.users) == 0 }

// email returns the pseudonym when s is an erased user's email address.
func (r *redactor) email(s string) (string, bool) {
	if r.empty() || s == "" || !strings.Contains(s, "@") {
		return "", false
	}
	p, ok := r.emails[valueHash(s)]
	return p, ok
}

// event replaces an erased user's email anywhere in the event, and their name in events about them (they are the
// actor, or their id appears in the target or the data). It marks the event Redacted; its Hash is the stored one.
func (r *redactor) event(e *AuditEvent) {
	if r.empty() {
		return
	}
	names := map[[32]byte]string{}
	about := func(s string) {
		if id, err := uuid.Parse(s); err == nil {
			if u, ok := r.users[id]; ok && u.name != nil {
				names[*u.name] = u.pseudonym
			}
		}
	}
	changed := false
	if e.Actor.ID != nil {
		if u, ok := r.users[*e.Actor.ID]; ok {
			about(e.Actor.ID.String())
			if e.Actor.Email != "" {
				e.Actor.Email, changed = u.pseudonym, true
			}
		}
	}
	if p, ok := r.email(e.Actor.Email); ok {
		e.Actor.Email, changed = p, true
	}
	for _, seg := range strings.Split(e.Target, "/") {
		about(seg)
	}
	var data any
	if len(e.Data) > 0 {
		dec := json.NewDecoder(bytes.NewReader(e.Data))
		dec.UseNumber()
		if dec.Decode(&data) == nil {
			walkStrings(data, func(s string) (string, bool) { about(s); return "", false })
			dataChanged := false
			data = rewriteStrings(data, func(s string) (string, bool) {
				if p, ok := r.email(s); ok {
					dataChanged = true
					return p, true
				}
				if len(names) > 0 && s != "" {
					if p, ok := names[valueHash(s)]; ok {
						dataChanged = true
						return p, true
					}
				}
				return "", false
			})
			if dataChanged {
				var b bytes.Buffer
				if writeCanonical(&b, data) == nil {
					e.Data, changed = b.Bytes(), true
				}
			}
		}
	}
	if changed {
		e.Redacted = true
	}
}

func walkStrings(v any, fn func(string) (string, bool)) { rewriteStrings(v, fn) }

func rewriteStrings(v any, fn func(string) (string, bool)) any {
	switch x := v.(type) {
	case string:
		if s, ok := fn(x); ok {
			return s
		}
	case []any:
		for i := range x {
			x[i] = rewriteStrings(x[i], fn)
		}
	case map[string]any:
		for k := range x {
			x[k] = rewriteStrings(x[k], fn)
		}
	}
	return v
}

// recordErasure remembers an erased user's email and name (as hashes) so readers can hide them.
func recordErasure(ctx context.Context, tx pgx.Tx, u User) error {
	var email, name []byte
	if u.Email != nil && *u.Email != "" {
		h := valueHash(*u.Email)
		email = h[:]
	}
	if u.DisplayName != nil && *u.DisplayName != "" {
		h := valueHash(*u.DisplayName)
		name = h[:]
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_redaction (user_id, pseudonym, email_hash, name_hash)
		VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING`, u.ID, Pseudonym(u.ID), email, name)
	return err
}
