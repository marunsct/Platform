// Package secrets encrypts the secrets maturad must keep (database server admin passwords, placement role
// passwords, webhook secrets) with envelope encryption (technical specification §9).
//
// Each value gets its own random 256-bit data key; the value is sealed with AES-256-GCM under the data key and the
// data key is sealed under the key-encryption key (KEK). Associated data binds each ciphertext to the row it belongs
// to, so a ciphertext copied into another row does not decrypt. OpenBao transit replaces the local KEK in TS17
// behind the same KeyManager interface.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeyManager seals and opens secrets. aad names the row the secret belongs to, e.g. "db_server:<id>".
type KeyManager interface {
	Seal(plaintext []byte, aad string) ([]byte, error)
	Open(ciphertext []byte, aad string) ([]byte, error)
	// Fingerprint identifies a secret for display without revealing it.
	Fingerprint(plaintext []byte) string
}

const version byte = 1

// Local is a KeyManager with a key-encryption key held in memory.
type Local struct {
	kek cipher.AEAD
	id  string // first bytes of the KEK's hash, stored with each ciphertext to detect a wrong KEK
}

// NewLocal builds a KeyManager from a base64-encoded 32-byte key.
func NewLocal(kekBase64 string) (*Local, error) {
	key, err := base64.StdEncoding.DecodeString(kekBase64)
	if err != nil || len(key) != 32 {
		return nil, errors.New("MATURA_KEK must be 32 random bytes, base64-encoded (openssl rand -base64 32)")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(key)
	return &Local{kek: aead, id: hex.EncodeToString(sum[:4])}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Layout: version(1) | kek id(8, hex) | sealed data key (nonce 12 + 32 + tag 16) | nonce(12) | sealed value.
const sealedKeyLen = 12 + 32 + 16

func (l *Local) Seal(plaintext []byte, aad string) ([]byte, error) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	keyNonce := make([]byte, 12)
	if _, err := rand.Read(keyNonce); err != nil {
		return nil, err
	}
	sealedKey := l.kek.Seal(keyNonce, keyNonce, dataKey, []byte(aad))

	data, err := newAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+8+len(sealedKey)+12+len(plaintext)+16)
	out = append(out, version)
	out = append(out, l.id...)
	out = append(out, sealedKey...)
	out = append(out, nonce...)
	return data.Seal(out, nonce, plaintext, []byte(aad)), nil
}

func (l *Local) Open(ct []byte, aad string) ([]byte, error) {
	if len(ct) < 1+8+sealedKeyLen+12+16 || ct[0] != version {
		return nil, errors.New("not a secret sealed by this version of maturad")
	}
	if string(ct[1:9]) != l.id {
		return nil, fmt.Errorf("secret was sealed with key-encryption key %s, not the configured one", ct[1:9])
	}
	sealedKey := ct[9 : 9+sealedKeyLen]
	dataKey, err := l.kek.Open(nil, sealedKey[:12], sealedKey[12:], []byte(aad))
	if err != nil {
		return nil, errors.New("cannot open secret: wrong key or it belongs to another row")
	}
	data, err := newAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	rest := ct[9+sealedKeyLen:]
	out, err := data.Open(nil, rest[:12], rest[12:], []byte(aad))
	if err != nil {
		return nil, errors.New("cannot open secret: it was changed")
	}
	return out, nil
}

func (l *Local) Fingerprint(plaintext []byte) string {
	sum := sha256.Sum256(append([]byte(l.id+":"), plaintext...))
	return "sha256:" + hex.EncodeToString(sum[:6])
}
