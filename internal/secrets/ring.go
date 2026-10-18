package secrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Wrapper protects data keys with a key-encryption key it holds or reaches: the local KEK, an OpenBao or Vault
// transit key, or a cloud KMS key (technical specification §9.1). aad binds a wrapped key to its use; a provider
// that cannot bind associated data itself binds a hash of it inside what it wraps.
type Wrapper interface {
	// ID names the key, e.g. "local:3f2a9c1d" or "transit:transit/matura". It is stored with every ciphertext, so
	// a key ring can find the wrapper that opens it after the primary changes.
	ID() string
	Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// ErrUnknownKey: a ciphertext names a key-encryption key the ring does not hold.
var ErrUnknownKey = errors.New("sealed with a key-encryption key this server is not configured with")

// Ring is a KeyManager over wrappers: new secrets are sealed under the primary; secrets sealed under any wrapper in
// the ring (an earlier primary during rotation) still open. It also opens the version 1 format of Local, under
// whichever local KEK in the ring sealed it.
type Ring struct {
	primary Wrapper
	byID    map[string]Wrapper
	fpSalt  string
	timeout time.Duration
	tenant  TenantOpener // opens version-3 (tenant key) ciphertexts; nil: they do not open
}

// TenantVersion marks secrets sealed under a tenant's own data-encryption key (technical specification §9.2); the
// ciphertext names the tenant and key version, and a TenantOpener (the store's tenant keys) opens it.
const TenantVersion byte = 3

// TenantOpener opens secrets sealed under a tenant key.
type TenantOpener interface {
	OpenTenant(ctx context.Context, ct []byte, aad string) ([]byte, error)
}

// SetTenantKeys lets the ring open tenant-key ciphertexts, so code that only holds the KeyManager opens them too.
func (r *Ring) SetTenantKeys(t TenantOpener) { r.tenant = t }

// NewRing returns a ring sealing under primary and opening under primary and others.
func NewRing(primary Wrapper, others ...Wrapper) *Ring {
	r := &Ring{primary: primary, byID: map[string]Wrapper{}, timeout: 10 * time.Second}
	for _, w := range append([]Wrapper{primary}, others...) {
		r.byID[w.ID()] = w
	}
	// fingerprints stay what Local gave so a database server's shown fingerprint does not change with the format
	if l, ok := primary.(*Local); ok {
		r.fpSalt = l.id
	} else {
		sum := sha256.Sum256([]byte(primary.ID()))
		r.fpSalt = hex.EncodeToString(sum[:4])
	}
	return r
}

// Primary is the wrapper new secrets are sealed under.
func (r *Ring) Primary() Wrapper { return r.primary }

// Wrapper returns the ring's wrapper with this id.
func (r *Ring) Wrapper(id string) (Wrapper, bool) {
	w, ok := r.byID[id]
	return w, ok
}

const ringVersion byte = 2

// Version-2 layout: 2 | id length (1) | id | wrapped key length (2) | wrapped key | nonce (12) | sealed value.

// Seal seals plaintext under a fresh data key wrapped by the primary.
func (r *Ring) Seal(plaintext []byte, aad string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.SealContext(ctx, plaintext, aad)
}

// SealContext is Seal with a context for providers that call out.
func (r *Ring) SealContext(ctx context.Context, plaintext []byte, aad string) ([]byte, error) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	wrapped, err := r.primary.Wrap(ctx, dataKey, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("wrap data key with %s: %w", r.primary.ID(), err)
	}
	id := r.primary.ID()
	if len(id) > 255 || len(wrapped) > 65535 {
		return nil, errors.New("key id or wrapped key too long")
	}
	aead, err := newAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(id)+len(wrapped)+12+len(plaintext)+16)
	out = append(out, ringVersion, byte(len(id)))
	out = append(out, id...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, []byte(aad)), nil
}

// Open opens a secret sealed by Seal (or by Local, version 1).
func (r *Ring) Open(ct []byte, aad string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.OpenContext(ctx, ct, aad)
}

// OpenContext is Open with a context.
func (r *Ring) OpenContext(ctx context.Context, ct []byte, aad string) ([]byte, error) {
	if len(ct) > 0 && ct[0] == TenantVersion {
		if r.tenant == nil {
			return nil, ErrUnknownKey
		}
		return r.tenant.OpenTenant(ctx, ct, aad)
	}
	if len(ct) > 9 && ct[0] == version {
		l, ok := r.byID["local:"+string(ct[1:9])].(*Local)
		if !ok {
			return nil, fmt.Errorf("%w (local:%s)", ErrUnknownKey, ct[1:9])
		}
		return l.Open(ct, aad)
	}
	id, wrapped, rest, err := parseRing(ct)
	if err != nil {
		return nil, err
	}
	w, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w (%s)", ErrUnknownKey, id)
	}
	dataKey, err := w.Unwrap(ctx, wrapped, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("cannot open secret: unwrap with %s: %w", id, err)
	}
	aead, err := newAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, rest[:12], rest[12:], []byte(aad))
	if err != nil {
		return nil, errors.New("cannot open secret: it was changed or belongs to another row")
	}
	return out, nil
}

// KeyID names the key-encryption key a ciphertext was sealed under ("" when it cannot be read).
func KeyID(ct []byte) string {
	if len(ct) > 9 && ct[0] == version {
		return "local:" + string(ct[1:9])
	}
	id, _, _, err := parseRing(ct)
	if err != nil {
		return ""
	}
	return id
}

func parseRing(ct []byte) (id string, wrapped, rest []byte, err error) {
	bad := errors.New("not a secret sealed by this version of maturad")
	if len(ct) < 2 || ct[0] != ringVersion {
		return "", nil, nil, bad
	}
	n := int(ct[1])
	if len(ct) < 2+n+2 {
		return "", nil, nil, bad
	}
	id = string(ct[2 : 2+n])
	m := int(binary.BigEndian.Uint16(ct[2+n:]))
	start := 2 + n + 2
	if len(ct) < start+m+12+16 {
		return "", nil, nil, bad
	}
	return id, ct[start : start+m], ct[start+m:], nil
}

// Rewrap re-seals a secret under the primary (key rotation). It returns the input unchanged when it already is, or
// when it is sealed under a tenant key.
func (r *Ring) Rewrap(ct []byte, aad string) ([]byte, bool, error) {
	if len(ct) > 0 && ct[0] == TenantVersion { // sealed under a tenant key: rewrap that key instead
		return ct, false, nil
	}
	if KeyID(ct) == r.primary.ID() && len(ct) > 0 && ct[0] == ringVersion {
		return ct, false, nil
	}
	plain, err := r.Open(ct, aad)
	if err != nil {
		return nil, false, err
	}
	out, err := r.Seal(plain, aad)
	return out, err == nil, err
}

func (r *Ring) Fingerprint(plaintext []byte) string {
	sum := sha256.Sum256(append([]byte(r.fpSalt+":"), plaintext...))
	return "sha256:" + hex.EncodeToString(sum[:6])
}

// --- the local KEK as a Wrapper -----------------------------------------------------------------------------------

func (l *Local) ID() string { return "local:" + l.id }

func (l *Local) Wrap(_ context.Context, dataKey, aad []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return l.kek.Seal(nonce, nonce, dataKey, aad), nil
}

func (l *Local) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < 12+16 {
		return nil, errors.New("wrapped key too short")
	}
	out, err := l.kek.Open(nil, wrapped[:12], wrapped[12:], aad)
	if err != nil {
		return nil, errors.New("wrong key or it belongs to another row")
	}
	return out, nil
}

// bindAAD and checkAAD bind associated data inside the wrapped bytes for providers whose wrap operation takes none
// (Azure Key Vault): the data key is followed by a hash of aad, checked on unwrap.
func bindAAD(dataKey, aad []byte) []byte {
	sum := sha256.Sum256(aad)
	return append(append([]byte{}, dataKey...), sum[:16]...)
}

func checkAAD(plain, aad []byte) ([]byte, error) {
	if len(plain) < 16 {
		return nil, errors.New("unwrapped key too short")
	}
	key, tag := plain[:len(plain)-16], plain[len(plain)-16:]
	sum := sha256.Sum256(aad)
	if string(tag) != string(sum[:16]) {
		return nil, errors.New("the wrapped key belongs to another row")
	}
	return key, nil
}
