package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marunsct/Platform/internal/secrets"
)

// Per-tenant keys (TS17, technical specification §9.2). Each tenant has a 256-bit tenant key per version, sealed by
// the installation's key ring or by the tenant's own key-encryption key (BYOK). Tenant secrets and the data keys apps
// use for field encryption are sealed under it in the version-3 format:
//
//	3 | tenant id (16) | key version (4) | nonce (12) | AES-256-GCM(tenant key, value, aad + "|tenant:" + id)
//
// so the ring opens them (it hands version 3 to TenantKeys) wherever a KeyManager is used. Destroying the keys
// makes all of it unreadable for good.

// ErrTenantKeyDestroyed: the tenant's keys were destroyed (crypto-shredded); what was sealed under them is gone.
var ErrTenantKeyDestroyed = errors.New("this organisation's keys were destroyed; data sealed under them cannot be read")

// TenantKeyUnavailableError: the tenant's own key-encryption key refused or could not be reached.
type TenantKeyUnavailableError struct{ Err error }

func (e *TenantKeyUnavailableError) Error() string {
	return "this organisation's own key-encryption key is not available: " + e.Err.Error()
}
func (e *TenantKeyUnavailableError) Unwrap() error { return e.Err }

// CustomerWrapper builds the wrapper for a tenant's own key from its provider and settings.
type CustomerWrapper func(provider string, config map[string]string) (secrets.Wrapper, error)

// TenantKeys seals and opens tenant secrets under tenant keys. Unwrapped keys are cached for TTL (default one
// minute): a key a tenant revokes at its own KMS stops working within that time on every replica.
type TenantKeys struct {
	st       *Store
	ring     *secrets.Ring
	customer CustomerWrapper
	ttl      time.Duration

	mu    sync.Mutex
	cache map[tenantKeyID]cachedKey
}

type tenantKeyID struct {
	tenant  uuid.UUID
	version int
}

type cachedKey struct {
	key []byte
	at  time.Time
}

// EnableTenantKeys turns on tenant keys for this store and lets ring open what they seal. customer may be nil
// (customer-managed keys off).
func (s *Store) EnableTenantKeys(ring *secrets.Ring, customer CustomerWrapper, ttl time.Duration) *TenantKeys {
	if ttl <= 0 {
		ttl = time.Minute
	}
	tk := &TenantKeys{st: s, ring: ring, customer: customer, ttl: ttl, cache: map[tenantKeyID]cachedKey{}}
	ring.SetTenantKeys(tk)
	s.tenantKeys = tk
	return tk
}

// TenantKeys returns the store's tenant keys (nil when not enabled).
func (s *Store) TenantKeys() *TenantKeys { return s.tenantKeys }

// ForTenant is the KeyManager that seals new secrets of a tenant under its tenant key when tenant keys are on, and
// under km otherwise; it opens anything km opens.
func (s *Store) ForTenant(km secrets.KeyManager, tenantID uuid.UUID) secrets.KeyManager {
	return s.forTenant(km, tenantID)
}

// forTenant seals new tenant secrets under the tenant key when tenant keys are on; otherwise under km itself.
func (s *Store) forTenant(km secrets.KeyManager, tenantID uuid.UUID) secrets.KeyManager {
	if s.tenantKeys == nil || tenantID == uuid.Nil {
		return km
	}
	return tenantKM{tk: s.tenantKeys, tenant: tenantID, base: km}
}

type tenantKM struct {
	tk     *TenantKeys
	tenant uuid.UUID
	base   secrets.KeyManager
}

func (k tenantKM) Seal(plain []byte, aad string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return k.tk.Seal(ctx, k.tenant, plain, aad)
}
func (k tenantKM) Open(ct []byte, aad string) ([]byte, error) { return k.base.Open(ct, aad) }
func (k tenantKM) Fingerprint(p []byte) string                { return k.base.Fingerprint(p) }

func tenantKeyAAD(tid uuid.UUID, v int) string {
	return "tenant_key:" + tid.String() + ":" + strconv.Itoa(v)
}
func providerAAD(tid uuid.UUID) string { return "tenant_key_provider:" + tid.String() }
func boundAAD(tid uuid.UUID, aad string) []byte {
	return []byte(aad + "|tenant:" + tid.String())
}

func (tk *TenantKeys) forget(tid uuid.UUID) {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	for k := range tk.cache {
		if k.tenant == tid {
			delete(tk.cache, k)
		}
	}
}

// provider loads the tenant's own key wrapper, or nil when it has none.
func (tk *TenantKeys) provider(ctx context.Context, tx pgx.Tx, tid uuid.UUID) (secrets.Wrapper, error) {
	var provider string
	var sealed []byte
	err := tx.QueryRow(ctx, `SELECT provider, config FROM tenant_key_provider WHERE tenant_id = $1`, tid).Scan(&provider, &sealed)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if tk.customer == nil {
		return nil, &TenantKeyUnavailableError{Err: errors.New("customer-managed keys are turned off on this installation")}
	}
	raw, err := tk.ring.OpenContext(ctx, sealed, providerAAD(tid))
	if err != nil {
		return nil, err
	}
	var cfg map[string]string
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return tk.customer(provider, cfg)
}

func (tk *TenantKeys) wrap(ctx context.Context, tx pgx.Tx, tid uuid.UUID, v int, key []byte) ([]byte, string, error) {
	w, err := tk.provider(ctx, tx, tid)
	if err != nil {
		return nil, "", err
	}
	if w != nil {
		out, err := w.Wrap(ctx, key, []byte(tenantKeyAAD(tid, v)))
		if err != nil {
			return nil, "", &TenantKeyUnavailableError{Err: err}
		}
		return out, "customer", nil
	}
	out, err := tk.ring.SealContext(ctx, key, tenantKeyAAD(tid, v))
	return out, "installation", err
}

func (tk *TenantKeys) unwrap(ctx context.Context, tx pgx.Tx, tid uuid.UUID, v int, wrapped []byte, sealedBy string) ([]byte, error) {
	if sealedBy == "customer" {
		w, err := tk.provider(ctx, tx, tid)
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, &TenantKeyUnavailableError{Err: errors.New("the key was sealed by the organisation's own key, which is no longer configured")}
		}
		key, err := w.Unwrap(ctx, wrapped, []byte(tenantKeyAAD(tid, v)))
		if err != nil {
			return nil, &TenantKeyUnavailableError{Err: err}
		}
		return key, nil
	}
	return tk.ring.OpenContext(ctx, wrapped, tenantKeyAAD(tid, v))
}

// keyAt returns version v of the tenant's key (from the cache when fresh).
func (tk *TenantKeys) keyAt(ctx context.Context, tid uuid.UUID, v int) ([]byte, error) {
	tk.mu.Lock()
	c, ok := tk.cache[tenantKeyID{tid, v}]
	tk.mu.Unlock()
	if ok && time.Since(c.at) < tk.ttl {
		return c.key, nil
	}
	var key []byte
	err := tk.st.tx(ctx, Scope{Operator: true, TenantID: tid}, func(tx pgx.Tx) error {
		var wrapped []byte
		var status, sealedBy string
		err := tx.QueryRow(ctx, `SELECT wrapped, status, sealed_by FROM tenant_key WHERE tenant_id = $1 AND version = $2`,
			tid, v).Scan(&wrapped, &status, &sealedBy)
		if err == pgx.ErrNoRows {
			return ErrTenantKeyDestroyed // no such key: never made, or the tenant row is gone
		}
		if err != nil {
			return err
		}
		if status == "destroyed" {
			return ErrTenantKeyDestroyed
		}
		key, err = tk.unwrap(ctx, tx, tid, v, wrapped, sealedBy)
		return err
	})
	if err != nil {
		return nil, err
	}
	tk.mu.Lock()
	tk.cache[tenantKeyID{tid, v}] = cachedKey{key: key, at: time.Now()}
	tk.mu.Unlock()
	return key, nil
}

// active returns the tenant's active key version, creating version 1 the first time.
func (tk *TenantKeys) active(ctx context.Context, tid uuid.UUID) (int, []byte, error) {
	var v int
	err := tk.st.tx(ctx, Scope{Operator: true, TenantID: tid}, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT version FROM tenant_key WHERE tenant_id = $1 AND status = 'active'`, tid).Scan(&v)
		if err != pgx.ErrNoRows {
			return err
		}
		var destroyed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_key WHERE tenant_id = $1 AND status = 'destroyed')`,
			tid).Scan(&destroyed); err != nil {
			return err
		}
		if destroyed {
			return ErrTenantKeyDestroyed
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		wrapped, by, err := tk.wrap(ctx, tx, tid, 1, key)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_key (tenant_id, version, wrapped, sealed_by, status)
			VALUES ($1, 1, $2, $3, 'active') ON CONFLICT DO NOTHING`, tid, wrapped, by); err != nil {
			return mapErr(err)
		}
		return tx.QueryRow(ctx, `SELECT version FROM tenant_key WHERE tenant_id = $1 AND status = 'active'`, tid).Scan(&v)
	})
	if err != nil {
		return 0, nil, err
	}
	key, err := tk.keyAt(ctx, tid, v)
	return v, key, err
}

// Seal seals plain under the tenant's active key.
func (tk *TenantKeys) Seal(ctx context.Context, tid uuid.UUID, plain []byte, aad string) ([]byte, error) {
	v, key, err := tk.active(ctx, tid)
	if err != nil {
		return nil, err
	}
	aead, err := secretsAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+16+4+12+len(plain)+16)
	out = append(out, secrets.TenantVersion)
	out = append(out, tid[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(v))
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, boundAAD(tid, aad)), nil
}

// TenantOf names the tenant a version-3 ciphertext belongs to.
func TenantOf(ct []byte) (uuid.UUID, int, bool) {
	if len(ct) < 1+16+4+12+16 || ct[0] != secrets.TenantVersion {
		return uuid.Nil, 0, false
	}
	tid, _ := uuid.FromBytes(ct[1:17])
	return tid, int(binary.BigEndian.Uint32(ct[17:21])), true
}

// OpenTenant opens a version-3 ciphertext (secrets.TenantOpener).
func (tk *TenantKeys) OpenTenant(ctx context.Context, ct []byte, aad string) ([]byte, error) {
	tid, v, ok := TenantOf(ct)
	if !ok {
		return nil, errors.New("not a tenant-sealed secret")
	}
	key, err := tk.keyAt(ctx, tid, v)
	if err != nil {
		return nil, err
	}
	aead, err := secretsAEAD(key)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, ct[21:33], ct[33:], boundAAD(tid, aad))
	if err != nil {
		return nil, errors.New("cannot open secret: it was changed or belongs to another row")
	}
	return out, nil
}

// TenantKeyInfo describes a tenant's keys without key material.
type TenantKeyInfo struct {
	Versions []TenantKeyVersion `json:"versions"`
	Provider *KeyProviderInfo   `json:"provider"`
}

type TenantKeyVersion struct {
	Version     int        `json:"version"`
	Status      string     `json:"status"`
	SealedBy    string     `json:"sealed_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DestroyedAt *time.Time `json:"destroyed_at"`
}

type KeyProviderInfo struct {
	Provider  string    `json:"provider"`
	KeyRef    string    `json:"key_ref"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Info lists the tenant's key versions and its own key, if any.
func (tk *TenantKeys) Info(ctx context.Context, sc Scope, tid uuid.UUID) (TenantKeyInfo, error) {
	out := TenantKeyInfo{Versions: []TenantKeyVersion{}}
	err := tk.st.tx(ctx, sc.InTenant(tid), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT version, status, sealed_by, created_at, destroyed_at FROM tenant_key
			WHERE tenant_id = $1 ORDER BY version DESC`, tid)
		if err != nil {
			return err
		}
		out.Versions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TenantKeyVersion, error) {
			var k TenantKeyVersion
			return k, r.Scan(&k.Version, &k.Status, &k.SealedBy, &k.CreatedAt, &k.DestroyedAt)
		})
		if err != nil {
			return err
		}
		var p KeyProviderInfo
		err = tx.QueryRow(ctx, `SELECT provider, key_ref, updated_at FROM tenant_key_provider WHERE tenant_id = $1`, tid).
			Scan(&p.Provider, &p.KeyRef, &p.UpdatedAt)
		if err == nil {
			out.Provider = &p
		} else if err != pgx.ErrNoRows {
			return err
		}
		return nil
	})
	return out, err
}

// Rotate makes a new key version active; earlier ones are retired but still open what they sealed.
func (tk *TenantKeys) Rotate(ctx context.Context, sc Scope, tid uuid.UUID) (int, error) {
	var v int
	err := tk.st.tx(ctx, sc.InTenant(tid), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tid); err != nil {
			return err
		}
		var destroyed bool
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0), coalesce(bool_or(status = 'destroyed'), false) FROM tenant_key
			WHERE tenant_id = $1`, tid).Scan(&v, &destroyed); err != nil {
			return err
		}
		if destroyed {
			return ErrTenantKeyDestroyed
		}
		v++
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		wrapped, by, err := tk.wrap(ctx, tx, tid, v, key)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_key SET status = 'retired' WHERE tenant_id = $1 AND status = 'active'`, tid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_key (tenant_id, version, wrapped, sealed_by, status)
			VALUES ($1, $2, $3, $4, 'active')`, tid, v, wrapped, by); err != nil {
			return mapErr(err)
		}
		return audit(ctx, tx, tid, "tenant_key.rotated", "tenants/"+tid.String()+"/keys", map[string]any{"version": v})
	})
	return v, err
}

// SetProvider makes the tenant's own key seal its tenant keys (BYOK): every live version is unwrapped and wrapped
// again under it, so revoking that key later makes the tenant's sealed data unreadable. config is kept sealed by
// the installation's ring; keyRef is what is shown.
func (tk *TenantKeys) SetProvider(ctx context.Context, sc Scope, tid uuid.UUID, provider, keyRef string, config map[string]string) error {
	if tk.customer == nil {
		return invalid("customer-managed keys are turned off on this installation (MATURA_BYOK_PROVIDERS)")
	}
	w, err := tk.customer(provider, config)
	if err != nil {
		return invalid("%s", err.Error())
	}
	probe := make([]byte, 32)
	_, _ = rand.Read(probe)
	wrapped, err := w.Wrap(ctx, probe, []byte("probe"))
	if err == nil {
		var back []byte
		back, err = w.Unwrap(ctx, wrapped, []byte("probe"))
		if err == nil && string(back) != string(probe) {
			err = errors.New("the key gave back something else")
		}
	}
	if err != nil {
		return invalid("the key does not wrap and unwrap: %s", err.Error())
	}
	if _, _, err := tk.active(ctx, tid); err != nil { // the tenant has at least one key to move
		return err
	}
	raw, _ := json.Marshal(config)
	err = tk.st.tx(ctx, sc.InTenant(tid), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tid); err != nil {
			return err
		}
		if err := tk.rewrapAll(ctx, tx, tid, func(v int, key []byte) ([]byte, string, error) {
			out, err := w.Wrap(ctx, key, []byte(tenantKeyAAD(tid, v)))
			return out, "customer", err
		}); err != nil {
			return err
		}
		sealed, err := tk.ring.SealContext(ctx, raw, providerAAD(tid))
		if err != nil {
			return err
		}
		v, err := nextVersion(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_key_provider (tenant_id, provider, key_ref, config, version, created_by)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id) DO UPDATE SET provider = EXCLUDED.provider,
			key_ref = EXCLUDED.key_ref, config = EXCLUDED.config, version = EXCLUDED.version, updated_at = now()`,
			tid, provider, keyRef, sealed, v, nilIfZero(sc.UserID)); err != nil {
			return mapErr(err)
		}
		return audit(ctx, tx, tid, "tenant_key.provider_set", "tenants/"+tid.String()+"/keys",
			map[string]any{"provider": provider, "key_ref": keyRef})
	})
	tk.forget(tid)
	return err
}

// ClearProvider seals the tenant keys under the installation's ring again (the tenant's own key must still work).
func (tk *TenantKeys) ClearProvider(ctx context.Context, sc Scope, tid uuid.UUID) error {
	err := tk.st.tx(ctx, sc.InTenant(tid), func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tid); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_key_provider WHERE tenant_id = $1)`, tid).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		if err := tk.rewrapAll(ctx, tx, tid, func(v int, key []byte) ([]byte, string, error) {
			out, err := tk.ring.SealContext(ctx, key, tenantKeyAAD(tid, v))
			return out, "installation", err
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM tenant_key_provider WHERE tenant_id = $1`, tid); err != nil {
			return err
		}
		return audit(ctx, tx, tid, "tenant_key.provider_removed", "tenants/"+tid.String()+"/keys", nil)
	})
	tk.forget(tid)
	return err
}

func (tk *TenantKeys) rewrapAll(ctx context.Context, tx pgx.Tx, tid uuid.UUID, wrap func(v int, key []byte) ([]byte, string, error)) error {
	rows, err := tx.Query(ctx, `SELECT version, wrapped, sealed_by FROM tenant_key WHERE tenant_id = $1 AND status <> 'destroyed'
		ORDER BY version FOR UPDATE`, tid)
	if err != nil {
		return err
	}
	type row struct {
		v       int
		wrapped []byte
		by      string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.v, &x.wrapped, &x.by)
	})
	if err != nil {
		return err
	}
	for _, x := range list {
		key, err := tk.unwrap(ctx, tx, tid, x.v, x.wrapped, x.by)
		if err != nil {
			return err
		}
		out, by, err := wrap(x.v, key)
		if err != nil {
			return &TenantKeyUnavailableError{Err: err}
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_key SET wrapped = $3, sealed_by = $4 WHERE tenant_id = $1 AND version = $2`,
			tid, x.v, out, by); err != nil {
			return err
		}
	}
	return nil
}

// destroyTenantKeys crypto-shreds a tenant: every key version is erased (wrapped set to NULL) and its own key
// provider forgotten. Called in the transaction that marks the tenant deleted.
func destroyTenantKeys(ctx context.Context, tx pgx.Tx, tid uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE tenant_key SET wrapped = NULL, status = 'destroyed', destroyed_at = now()
		WHERE tenant_id = $1 AND status <> 'destroyed'`, tid)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_key_provider WHERE tenant_id = $1`, tid); err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// no key yet: record a destroyed version 1 so none is ever made for this tenant again
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_key (tenant_id, version, wrapped, sealed_by, status, destroyed_at)
			VALUES ($1, 1, NULL, 'installation', 'destroyed', now()) ON CONFLICT DO NOTHING`, tid); err != nil {
			return err
		}
	}
	return audit(ctx, tx, tid, "tenant_key.destroyed", "tenants/"+tid.String()+"/keys",
		map[string]any{"versions": tag.RowsAffected()})
}

// --- data keys for apps (SDK field encryption) ---------------------------------------------------------------------

// DataKey is a fresh 256-bit key an app encrypts fields with, and the same key sealed under the tenant key (what
// the app stores next to its data, and unwraps later).
type DataKey struct {
	Plaintext []byte `json:"plaintext"`
	Wrapped   []byte `json:"wrapped"`
	Version   int    `json:"key_version"`
}

func dataKeyAAD(appID uuid.UUID) string { return "app_data_key:" + appID.String() }

func (tk *TenantKeys) checkApp(ctx context.Context, app App, tid uuid.UUID) error {
	return tk.st.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM tenant_app WHERE tenant_id = $1 AND app_id = $2`, tid, app.ID).Scan(&status)
		if err == pgx.ErrNoRows || (err == nil && status != "enabled") {
			return ErrNotFound
		}
		return err
	})
}

// NewDataKey gives an app a data key for one tenant (the tenant must have it enabled).
func (tk *TenantKeys) NewDataKey(ctx context.Context, app App, tid uuid.UUID) (DataKey, error) {
	if err := tk.checkApp(ctx, app, tid); err != nil {
		return DataKey{}, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return DataKey{}, err
	}
	sealed, err := tk.Seal(ctx, tid, key, dataKeyAAD(app.ID))
	if err != nil {
		return DataKey{}, err
	}
	_, v, _ := TenantOf(sealed)
	return DataKey{Plaintext: key, Wrapped: sealed, Version: v}, nil
}

// UnwrapDataKey opens a data key the app got for this tenant.
func (tk *TenantKeys) UnwrapDataKey(ctx context.Context, app App, tid uuid.UUID, wrapped []byte) ([]byte, error) {
	if owner, _, ok := TenantOf(wrapped); !ok || owner != tid {
		return nil, invalid("this is not a data key of this organisation")
	}
	if err := tk.checkApp(ctx, app, tid); err != nil {
		return nil, err
	}
	out, err := tk.OpenTenant(ctx, wrapped, dataKeyAAD(app.ID))
	if err != nil && !errors.Is(err, ErrTenantKeyDestroyed) && !errors.As(err, new(*TenantKeyUnavailableError)) {
		return nil, invalid("this data key does not open: %s", err.Error())
	}
	return out, err
}

// --- rewrapping installation secrets (KEK rotation) ----------------------------------------------------------------

// RewrapResult counts what RewrapSecrets changed.
type RewrapResult struct {
	Rewrapped int            `json:"rewrapped"`
	Unchanged int            `json:"unchanged"`
	Failed    map[string]int `json:"failed"`
}

// RewrapSecrets re-seals every stored secret and installation-sealed tenant key under the ring's primary key, so
// earlier key-encryption keys can be removed from the configuration. Secrets sealed under tenant keys are left as
// they are (their tenant keys are rewrapped).
func (s *Store) RewrapSecrets(ctx context.Context, ring *secrets.Ring) (RewrapResult, error) {
	res := RewrapResult{Failed: map[string]int{}}
	type col struct {
		table, key, column string
		aad                func(id string) string
	}
	idAAD := func(prefix string) func(string) string { return func(id string) string { return prefix + id } }
	cols := []col{
		{"db_server", "id", "admin_secret", idAAD("db_server:")},
		{"placement", "id", "role_secret", func(id string) string { return "placement:" + id + ":runtime" }},
		{"placement", "id", "owner_role_secret", func(id string) string { return "placement:" + id + ":owner" }},
		{"webhook_endpoint", "id", "secret", idAAD("webhook:")},
		{"audit_sink", "id", "secret", idAAD("audit_sink:")},
		{"tenant_sso", "tenant_id", "client_secret", idAAD("tenant_sso:")},
		{"tenant_key_provider", "tenant_id", "config", idAAD("tenant_key_provider:")},
	}
	err := s.tx(ctx, Scope{Operator: true}, func(tx pgx.Tx) error {
		for _, c := range cols {
			rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT %s::text, %s FROM %s WHERE %s IS NOT NULL FOR UPDATE`,
				c.key, c.column, c.table, c.column))
			if err != nil {
				return err
			}
			type item struct {
				id string
				ct []byte
			}
			items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
				var x item
				return x, r.Scan(&x.id, &x.ct)
			})
			if err != nil {
				return err
			}
			for _, it := range items {
				out, changed, err := ring.Rewrap(it.ct, c.aad(it.id))
				switch {
				case err != nil:
					res.Failed[c.table+"."+c.column]++
				case !changed:
					res.Unchanged++
				default:
					if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s = $2 WHERE %s::text = $1`, c.table, c.column, c.key),
						it.id, out); err != nil {
						return err
					}
					res.Rewrapped++
				}
			}
		}
		rows, err := tx.Query(ctx, `SELECT tenant_id, version, wrapped FROM tenant_key WHERE sealed_by = 'installation'
			AND status <> 'destroyed' FOR UPDATE`)
		if err != nil {
			return err
		}
		type key struct {
			tid     uuid.UUID
			v       int
			wrapped []byte
		}
		keys, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (key, error) {
			var k key
			return k, r.Scan(&k.tid, &k.v, &k.wrapped)
		})
		if err != nil {
			return err
		}
		for _, k := range keys {
			out, changed, err := ring.Rewrap(k.wrapped, tenantKeyAAD(k.tid, k.v))
			switch {
			case err != nil:
				res.Failed["tenant_key.wrapped"]++
			case !changed:
				res.Unchanged++
			default:
				if _, err := tx.Exec(ctx, `UPDATE tenant_key SET wrapped = $3 WHERE tenant_id = $1 AND version = $2`,
					k.tid, k.v, out); err != nil {
					return err
				}
				res.Rewrapped++
			}
		}
		return audit(ctx, tx, uuid.Nil, "keys.rewrapped", "installation/keys",
			map[string]any{"rewrapped": res.Rewrapped, "unchanged": res.Unchanged, "failed": res.Failed, "key": ring.Primary().ID()})
	})
	return res, err
}

func secretsAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
