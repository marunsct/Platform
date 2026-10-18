package matura

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Field encryption under tenant keys (technical specification §9.2). A FieldCipher gets a data key per tenant from
// maturad, encrypts fields with it locally (AES-256-GCM), and stores the data key sealed under the tenant key inside
// each value, so it can be opened again later — and never again once the tenant is deleted (crypto-shredding).

// ErrTenantKeyDestroyed: the tenant was deleted and its keys destroyed; the value cannot be decrypted, ever.
var ErrTenantKeyDestroyed = errors.New("matura: the tenant's keys were destroyed")

// ErrTenantKeyUnavailable: the tenant's own key-encryption key (BYOK) refused or was not reachable; retry later.
var ErrTenantKeyUnavailable = errors.New("matura: the tenant's own key is not available")

const fieldPrefix = "mfe1:"

// FieldCipher encrypts and decrypts fields of one app for any tenant. Safe for concurrent use.
type FieldCipher struct {
	Client *Client
	App    string        // the app's slug
	MaxAge time.Duration // how long one data key encrypts new values (default 1 hour)

	mu        sync.Mutex
	current   map[string]fieldKey // tenant -> data key used for new values
	unwrapped map[string]fieldKey // sealed data key (base64) -> key
}

type fieldKey struct {
	key     []byte
	wrapped string // base64
	at      time.Time
}

func (f *FieldCipher) path(tenant string) string {
	return "/v1/apps/" + seg(f.App) + "/tenants/" + seg(tenant) + "/data-keys"
}

func keyError(err error) error {
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusGone:
			return ErrTenantKeyDestroyed
		case http.StatusServiceUnavailable:
			return ErrTenantKeyUnavailable
		}
	}
	return err
}

func (f *FieldCipher) keyFor(ctx context.Context, tenant string) (fieldKey, error) {
	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	f.mu.Lock()
	k, ok := f.current[tenant]
	f.mu.Unlock()
	if ok && time.Since(k.at) < maxAge {
		return k, nil
	}
	var out struct {
		Plaintext []byte `json:"plaintext"`
		Wrapped   []byte `json:"wrapped"`
	}
	if err := f.Client.do(ctx, http.MethodPost, f.path(tenant), nil, nil, &out, false); err != nil {
		return fieldKey{}, keyError(err)
	}
	k = fieldKey{key: out.Plaintext, wrapped: base64.RawURLEncoding.EncodeToString(out.Wrapped), at: time.Now()}
	f.mu.Lock()
	if f.current == nil {
		f.current, f.unwrapped = map[string]fieldKey{}, map[string]fieldKey{}
	}
	f.current[tenant] = k
	f.unwrapped[k.wrapped] = k
	f.mu.Unlock()
	return k, nil
}

func (f *FieldCipher) unwrap(ctx context.Context, tenant, wrapped string) ([]byte, error) {
	f.mu.Lock()
	k, ok := f.unwrapped[wrapped]
	f.mu.Unlock()
	if ok && time.Since(k.at) < 5*time.Minute { // re-check now and then, so a destroyed key stops working
		return k.key, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, errors.New("matura: not an encrypted field")
	}
	var out struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := f.Client.do(ctx, http.MethodPost, f.path(tenant)+":unwrap", nil, map[string]any{"wrapped": raw}, &out, false); err != nil {
		return nil, keyError(err)
	}
	f.mu.Lock()
	if f.unwrapped == nil {
		f.current, f.unwrapped = map[string]fieldKey{}, map[string]fieldKey{}
	}
	f.unwrapped[wrapped] = fieldKey{key: out.Plaintext, wrapped: wrapped, at: time.Now()}
	f.mu.Unlock()
	return out.Plaintext, nil
}

// Encrypt returns a text value ("mfe1:…") to store instead of plaintext. aad binds it to its place (say the table,
// column and row id): Decrypt must be given the same.
func (f *FieldCipher) Encrypt(ctx context.Context, tenant string, plaintext, aad []byte) (string, error) {
	k, err := f.keyFor(ctx, tenant)
	if err != nil {
		return "", err
	}
	aead, err := gcm(k.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, fieldAAD(tenant, aad))
	return fieldPrefix + k.wrapped + ":" + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value Encrypt made for the same tenant and aad.
func (f *FieldCipher) Decrypt(ctx context.Context, tenant, value string, aad []byte) ([]byte, error) {
	rest, ok := strings.CutPrefix(value, fieldPrefix)
	wrapped, body, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 {
		return nil, errors.New("matura: not an encrypted field")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, errors.New("matura: not an encrypted field")
	}
	key, err := f.unwrap(ctx, tenant, wrapped)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("matura: not an encrypted field")
	}
	out, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], fieldAAD(tenant, aad))
	if err != nil {
		return nil, errors.New("matura: the field was changed, or belongs to another tenant or place")
	}
	return out, nil
}

// Forget drops cached keys of a tenant (for example on matura.tenant.deleted).
func (f *FieldCipher) Forget(tenant string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.current, tenant)
	f.unwrapped = map[string]fieldKey{}
}

func fieldAAD(tenant string, aad []byte) []byte {
	return append([]byte("tenant:"+tenant+"|"), aad...)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
