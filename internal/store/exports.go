package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/ids"
)

// Tenant data export (technical specification §14.1).

var (
	// MaxExportBytes caps a tenant export bundle; a larger one fails and the audit log can be exported on its own.
	MaxExportBytes = 64 << 20
	// ExportTTL is how long a ready bundle can be downloaded before the worker clears it.
	ExportTTL = 24 * time.Hour
	// ErrExportExpired is a bundle that was cleared.
	ErrExportExpired = errors.New("this export has expired; start a new one")
)

// ExportFormat names the bundle's layout; it changes only incompatibly.
const ExportFormat = "matura.tenant-export/v1"

type TenantExport struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	RequestedBy *uuid.UUID `json:"requested_by"`
	State       string     `json:"state"` // queued, running, ready, failed, expired
	SizeBytes   *int64     `json:"size_bytes"`
	SHA256      *string    `json:"sha256"`
	Error       *string    `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

const exportCols = `id, tenant_id, requested_by, state, size_bytes, sha256, error, created_at, finished_at, expires_at`

func scanExport(row pgx.Row) (TenantExport, error) {
	var e TenantExport
	var sum []byte
	err := row.Scan(&e.ID, &e.TenantID, &e.RequestedBy, &e.State, &e.SizeBytes, &sum, &e.Error, &e.CreatedAt,
		&e.FinishedAt, &e.ExpiresAt)
	if len(sum) > 0 {
		h := hex.EncodeToString(sum)
		e.SHA256 = &h
	}
	return e, mapErr(err)
}

func exportTarget(e TenantExport) string {
	return "tenants/" + e.TenantID.String() + "/exports/" + e.ID.String()
}

// CreateExport queues an export of the tenant's data. One runs at a time per tenant.
func (s *Store) CreateExport(ctx context.Context, sc Scope, tenantID uuid.UUID) (TenantExport, error) {
	var out TenantExport
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var by any
		if sc.UserID != uuid.Nil {
			by = sc.UserID
		}
		var err error
		out, err = scanExport(tx.QueryRow(ctx, `INSERT INTO tenant_export (id, tenant_id, requested_by, state)
			VALUES ($1, $2, $3, 'queued') RETURNING `+exportCols, ids.New(), tenantID, by))
		if errors.Is(err, ErrConflict) {
			return fmt.Errorf("%w: an export of this tenant is already in progress", ErrConflict)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "tenant_export.requested", exportTarget(out), out)
	})
	return out, err
}

func (s *Store) ListExports(ctx context.Context, sc Scope, tenantID uuid.UUID) ([]TenantExport, error) {
	var out []TenantExport
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+exportCols+` FROM tenant_export WHERE tenant_id = $1
			ORDER BY created_at DESC LIMIT 50`, tenantID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TenantExport, error) { return scanExport(r) })
		return err
	})
	return out, err
}

func (s *Store) GetExport(ctx context.Context, sc Scope, tenantID, id uuid.UUID) (TenantExport, error) {
	var out TenantExport
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) (err error) {
		out, err = scanExport(tx.QueryRow(ctx, `SELECT `+exportCols+` FROM tenant_export WHERE tenant_id = $1 AND id = $2`,
			tenantID, id))
		return err
	})
	return out, err
}

// ExportBundle returns a ready export's bundle and records the download in the tenant's audit log.
func (s *Store) ExportBundle(ctx context.Context, sc Scope, tenantID, id uuid.UUID) (TenantExport, []byte, error) {
	var out TenantExport
	var bundle []byte
	err := s.tx(ctx, sc.InTenant(tenantID), func(tx pgx.Tx) error {
		var err error
		out, err = scanExport(tx.QueryRow(ctx, `SELECT `+exportCols+` FROM tenant_export WHERE tenant_id = $1 AND id = $2`,
			tenantID, id))
		if err != nil {
			return err
		}
		switch {
		case out.State == "expired" || out.State == "ready" && out.ExpiresAt != nil && !out.ExpiresAt.After(time.Now()):
			return ErrExportExpired
		case out.State != "ready":
			return fmt.Errorf("%w: the export is %s, not ready", ErrConflict, out.State)
		}
		if err := tx.QueryRow(ctx, `SELECT bundle FROM tenant_export WHERE id = $1`, id).Scan(&bundle); err != nil {
			return err
		}
		return audit(ctx, tx, tenantID, "tenant_export.downloaded", exportTarget(out),
			map[string]any{"id": out.ID, "sha256": out.SHA256, "size_bytes": out.SizeBytes})
	})
	if err == nil {
		bundle, err = s.openBundle(ctx, tenantID, id, bundle)
	}
	return out, bundle, err
}

func exportAAD(id uuid.UUID) string { return "tenant_export:" + id.String() }

// sealBundle seals a bundle under the tenant's key when tenant keys are on (technical specification §9.2), so a
// bundle at rest is shredded with the tenant's keys.
func (s *Store) sealBundle(ctx context.Context, tid, id uuid.UUID, bundle []byte) ([]byte, error) {
	if s.tenantKeys == nil {
		return bundle, nil
	}
	return s.tenantKeys.Seal(ctx, tid, bundle, exportAAD(id))
}

// openBundle opens a sealed bundle; bundles stored before tenant keys were turned on are plain zip files.
func (s *Store) openBundle(ctx context.Context, tid, id uuid.UUID, bundle []byte) ([]byte, error) {
	if owner, _, sealed := TenantOf(bundle); !sealed || owner != tid {
		return bundle, nil
	}
	if s.tenantKeys == nil {
		return nil, errors.New("the export is sealed under the tenant's key and tenant keys are not configured")
	}
	return s.tenantKeys.OpenTenant(ctx, bundle, exportAAD(id))
}

// ClaimExport takes the oldest queued export (or one whose worker died while running it) for the privacy worker.
func (s *Store) ClaimExport(ctx context.Context) (TenantExport, error) {
	var out TenantExport
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) (err error) {
		out, err = scanExport(tx.QueryRow(ctx, `UPDATE tenant_export SET state = 'running', started_at = now()
			WHERE id = (SELECT id FROM tenant_export
				WHERE state = 'queued' OR state = 'running' AND started_at < now() - interval '15 minutes'
				ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
			RETURNING `+exportCols))
		return err
	})
	return out, err
}

// FinishExport stores the bundle and makes it downloadable for ExportTTL. A bundle over MaxExportBytes fails the
// export instead.
func (s *Store) FinishExport(ctx context.Context, e TenantExport, bundle []byte) (TenantExport, error) {
	if len(bundle) > MaxExportBytes {
		return s.FailExport(ctx, e, fmt.Sprintf("the export is %d bytes, more than the %d allowed; export the audit "+
			"log separately (GET /v1/tenants/{tid}/audit/export)", len(bundle), MaxExportBytes))
	}
	sum := sha256.Sum256(bundle)
	stored, err := s.sealBundle(ctx, e.TenantID, e.ID, bundle)
	if err != nil {
		return TenantExport{}, err
	}
	var out TenantExport
	err = s.tx(ctx, Scope{TenantID: e.TenantID}, func(tx pgx.Tx) (err error) {
		out, err = scanExport(tx.QueryRow(ctx, `UPDATE tenant_export SET state = 'ready', bundle = $3,
			size_bytes = $4, sha256 = $5, finished_at = now(), expires_at = now() + $6::interval, error = NULL
			WHERE tenant_id = $1 AND id = $2 RETURNING `+exportCols,
			e.TenantID, e.ID, stored, len(bundle), sum[:], fmt.Sprintf("%d seconds", int(ExportTTL.Seconds()))))
		if err != nil {
			return err
		}
		return audit(ctx, tx, e.TenantID, "tenant_export.completed", exportTarget(out), out)
	})
	return out, err
}

func (s *Store) FailExport(ctx context.Context, e TenantExport, reason string) (TenantExport, error) {
	var out TenantExport
	err := s.tx(ctx, Scope{TenantID: e.TenantID}, func(tx pgx.Tx) (err error) {
		out, err = scanExport(tx.QueryRow(ctx, `UPDATE tenant_export SET state = 'failed', error = $3,
			finished_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING `+exportCols, e.TenantID, e.ID, reason))
		if err != nil {
			return err
		}
		return audit(ctx, tx, e.TenantID, "tenant_export.failed", exportTarget(out), out)
	})
	return out, err
}

// ExpireExports clears bundles past their expiry.
func (s *Store) ExpireExports(ctx context.Context) (int64, error) {
	var n int64
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tenant_export SET state = 'expired', bundle = NULL
			WHERE state = 'ready' AND expires_at <= now()`)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// TenantBundle is what a tenant export holds. Secrets (placement passwords, invitation tokens, sink secrets) are
// never included; erased users appear under their pseudonym.
type TenantBundle struct {
	Format         string         `json:"format"`
	ExportID       uuid.UUID      `json:"export_id"`
	GeneratedAt    time.Time      `json:"generated_at"`
	Tenant         Tenant         `json:"tenant"`
	Workspaces     []Workspace    `json:"workspaces"`
	Members        []Membership   `json:"members"`
	Invitations    []Invitation   `json:"invitations"`
	Grants         []Grant        `json:"grants"`
	Roles          []Role         `json:"roles"` // the app roles the grants use
	Placements     []Placement    `json:"placements"`
	SecurityPolicy SecurityPolicy `json:"security_policy"`
	Retention      Retention      `json:"retention"`
	Audit          BundleAudit    `json:"audit"`
}

// BundleAudit is the tenant's audit chain from its anchor to its head, with hashes, so the receiver can check it.
type BundleAudit struct {
	AnchorSeq  int64        `json:"anchor_seq"`
	AnchorHash string       `json:"anchor_hash"`
	HeadSeq    int64        `json:"head_seq"`
	HeadHash   string       `json:"head_hash"`
	Events     []AuditEvent `json:"events"`
}

// BuildTenantBundle reads everything Matura holds about the tenant in one repeatable-read snapshot.
func (s *Store) BuildTenantBundle(ctx context.Context, tenantID, exportID uuid.UUID) ([]byte, error) {
	b := TenantBundle{Format: ExportFormat, ExportID: exportID, GeneratedAt: time.Now().UTC()}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			if err := setScope(ctx, tx, Scope{TenantID: tenantID}); err != nil {
				return err
			}
			red, err := loadRedactor(ctx, tx)
			if err != nil {
				return err
			}
			if b.Tenant, err = scanTenant(tx.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenant WHERE id = $1`, tenantID)); err != nil {
				return err
			}
			list := func(q string, scan func(pgx.CollectableRow) error) error {
				rows, err := tx.Query(ctx, q, tenantID)
				if err != nil {
					return err
				}
				_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) { return struct{}{}, scan(r) })
				return err
			}
			steps := []struct {
				q    string
				scan func(pgx.CollectableRow) error
			}{
				{`SELECT ` + workspaceCols + ` FROM workspace WHERE tenant_id = $1 AND status <> 'deleted'
					ORDER BY is_default DESC, name`,
					func(r pgx.CollectableRow) error {
						w, err := scanWorkspace(r)
						b.Workspaces = append(b.Workspaces, w)
						return err
					}},
				{`SELECT ` + memberCols + ` FROM membership m JOIN app_user u ON u.id = m.user_id
					WHERE m.tenant_id = $1 AND m.status <> 'removed' ORDER BY lower(u.email)`,
					func(r pgx.CollectableRow) error {
						m, err := scanMember(r)
						b.Members = append(b.Members, m)
						return err
					}},
				{`SELECT ` + invitationCols + ` FROM invitation WHERE tenant_id = $1 ORDER BY created_at DESC`,
					func(r pgx.CollectableRow) error {
						i, err := scanInvitation(r)
						b.Invitations = append(b.Invitations, i)
						return err
					}},
				{`SELECT ` + grantCols + ` FROM role_grant g JOIN app a ON a.id = g.app_id
					WHERE g.tenant_id = $1 AND g.status = 'active' ORDER BY a.slug, g.role, g.id`,
					func(r pgx.CollectableRow) error { g, err := scanGrant(r); b.Grants = append(b.Grants, g); return err }},
				{`SELECT ` + roleCols + ` FROM app_role r JOIN app a ON a.id = r.app_id
					WHERE (r.app_id, r.name) IN (SELECT app_id, role FROM role_grant WHERE tenant_id = $1 AND status = 'active')
					ORDER BY a.slug, r.name`,
					func(r pgx.CollectableRow) error { x, err := scanRole(r); b.Roles = append(b.Roles, x); return err }},
				{`SELECT ` + placementCols + ` FROM placement WHERE tenant_id = $1 ORDER BY created_at`,
					func(r pgx.CollectableRow) error {
						p, err := scanPlacement(r)
						b.Placements = append(b.Placements, p)
						return err
					}},
			}
			for _, st := range steps {
				if err := list(st.q, st.scan); err != nil {
					return err
				}
			}
			if b.SecurityPolicy, err = getPolicy(ctx, tx, tenantID); err != nil {
				return err
			}
			if b.Retention, err = getRetention(ctx, tx, tenantID); err != nil {
				return err
			}
			var head, anchor []byte
			err = tx.QueryRow(ctx, `SELECT seq, hash, anchor_seq, anchor_hash FROM audit_chain WHERE chain = $1`, tenantID).
				Scan(&b.Audit.HeadSeq, &head, &b.Audit.AnchorSeq, &anchor)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if len(anchor) == 0 {
				anchor = genesis
			}
			if len(head) == 0 {
				head = genesis
			}
			b.Audit.HeadHash, b.Audit.AnchorHash = hex.EncodeToString(head), hex.EncodeToString(anchor)
			for after := b.Audit.AnchorSeq; ; {
				page, err := chainPage(ctx, tx, tenantID, after, 1000, nil, nil)
				if err != nil {
					return err
				}
				for i := range page {
					red.event(&page[i])
					after = page[i].Seq
				}
				b.Audit.Events = append(b.Audit.Events, page...)
				if len(page) < 1000 {
					return nil
				}
			}
		})
	if err != nil {
		return nil, mapErr(err)
	}
	b.Workspaces, b.Members, b.Invitations = nonNilSlice(b.Workspaces), nonNilSlice(b.Members), nonNilSlice(b.Invitations)
	b.Grants, b.Roles, b.Placements = nonNilSlice(b.Grants), nonNilSlice(b.Roles), nonNilSlice(b.Placements)
	b.Audit.Events = nonNilSlice(b.Audit.Events)
	return json.Marshal(b)
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
