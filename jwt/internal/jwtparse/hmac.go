package jwtparse

import (
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
	"hash"
	"sync"
	"unsafe"
)

type signingMethodHMAC struct {
	alg  string
	hash crypto.Hash
	pool sync.Pool // stores *hmacEntry
}

type hmacEntry struct {
	mac hash.Hash
	key []byte // key used to create this hasher
}

// HMAC-SHA signing method singletons.
var (
	SigningMethodHS256 *signingMethodHMAC
	SigningMethodHS384 *signingMethodHMAC
	SigningMethodHS512 *signingMethodHMAC
)

func init() {
	SigningMethodHS256 = &signingMethodHMAC{alg: "HS256", hash: crypto.SHA256}
	SigningMethodHS384 = &signingMethodHMAC{alg: "HS384", hash: crypto.SHA384}
	SigningMethodHS512 = &signingMethodHMAC{alg: "HS512", hash: crypto.SHA512}

	RegisterSigningMethod(SigningMethodHS256)
	RegisterSigningMethod(SigningMethodHS384)
	RegisterSigningMethod(SigningMethodHS512)
}

func (m *signingMethodHMAC) Alg() string { return m.alg }

func (m *signingMethodHMAC) getHMAC(key []byte) *hmacEntry {
	if v := m.pool.Get(); v != nil {
		e := v.(*hmacEntry)
		if len(e.key) == len(key) && subtle.ConstantTimeCompare(e.key, key) == 1 {
			e.mac.Reset()
			return e
		}
	}
	mac := hmac.New(func() hash.Hash { return m.hash.New() }, key)
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &hmacEntry{mac: mac, key: keyCopy}
}

func (m *signingMethodHMAC) putHMAC(e *hmacEntry) {
	m.pool.Put(e)
}

func (m *signingMethodHMAC) Verify(signingInput string, sig []byte, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%w: HMAC key must be []byte", ErrTokenUnverifiable)
	}
	if len(keyBytes) == 0 {
		return fmt.Errorf("%w: HMAC key is empty", ErrTokenUnverifiable)
	}

	entry := m.getHMAC(keyBytes)
	entry.mac.Write(stringToBytes(signingInput))

	var buf [64]byte
	expected := entry.mac.Sum(buf[:0])
	m.putHMAC(entry)

	if !hmac.Equal(sig, expected) {
		return ErrTokenSignatureInvalid
	}
	return nil
}

func (m *signingMethodHMAC) Sign(signingInput string, key any) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: HMAC key must be []byte", ErrTokenUnverifiable)
	}
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("%w: HMAC key is empty", ErrTokenUnverifiable)
	}

	entry := m.getHMAC(keyBytes)
	entry.mac.Write(stringToBytes(signingInput))
	result := entry.mac.Sum(nil)
	m.putHMAC(entry)
	return result, nil
}

// stringToBytes converts a string to []byte without copying.
// The returned slice MUST NOT be modified.
func stringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
