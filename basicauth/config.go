package basicauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"github.com/goceleris/celeris"
)

// UsernameKey is the context store key for the authenticated username.
const UsernameKey = "basicauth_username"

// Config defines the basic auth middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// Validator checks credentials. Required if Users is nil -- panics if both are nil.
	Validator func(user, pass string) bool

	// ValidatorWithContext checks credentials with access to the request context.
	// Takes precedence over Validator when set. Useful for per-request auth decisions
	// (e.g., tenant-based authentication, IP-aware rate limiting within auth).
	ValidatorWithContext func(c *celeris.Context, user, pass string) bool

	// Users maps usernames to passwords. When set and Validator is nil,
	// a constant-time validator is auto-generated from this map.
	Users map[string]string

	// HashedUsers maps usernames to hex-encoded SHA-256 password hashes.
	// When set and Validator, ValidatorWithContext, and Users are all nil,
	// a constant-time validator is auto-generated that SHA-256 hashes the
	// incoming password and compares it against the stored hash.
	// Use [HashPassword] to produce the hex-encoded hash values.
	HashedUsers map[string]string

	// Realm is the authentication realm. Default: "Restricted".
	Realm string

	// HeaderLimit is the maximum allowed length of the Authorization header
	// in bytes. Requests exceeding this limit receive a 431 (Request Header
	// Fields Too Large) response via ErrorHandler. Default: 4096.
	HeaderLimit int

	// ErrorHandler handles authentication failures. The err parameter is
	// the sentinel error that triggered the failure: [ErrUnauthorized] (401)
	// for missing/invalid credentials, [ErrBadRequest] (400) for malformed
	// headers, or [ErrHeaderTooLarge] (431) for oversized headers.
	// Default: 401 with WWW-Authenticate + Cache-Control + Vary headers.
	ErrorHandler func(c *celeris.Context, err error) error
}

// defaultConfig is the default basic auth configuration.
// Unexported to prevent callers from mutating shared state.
var defaultConfig = Config{
	Realm: "Restricted",
}

// DefaultConfig returns a copy of the default configuration.
func DefaultConfig() Config {
	return defaultConfig
}

// hmacKey generates a 32-byte cryptographically random key.
func hmacKey() [32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic("basicauth: crypto/rand failed: " + err.Error())
	}
	return key
}

func applyDefaults(cfg Config) Config {
	if cfg.Realm == "" {
		cfg.Realm = defaultConfig.Realm
	}
	if cfg.HeaderLimit <= 0 {
		cfg.HeaderLimit = 4096
	}
	if cfg.Validator == nil && cfg.ValidatorWithContext == nil && len(cfg.Users) > 0 {
		// Deep-copy the map so post-New() mutations don't affect the validator.
		type userEntry struct{ passBytes []byte }
		entries := make(map[string]userEntry, len(cfg.Users))
		for u, p := range cfg.Users {
			entries[u] = userEntry{passBytes: []byte(p)}
		}
		// Per-instance HMAC key equalizes lengths for constant-time comparison.
		key := hmacKey()
		// Random dummy value for unknown-user comparisons to prevent
		// timing side-channels on username existence.
		dummyMAC := hmacSHA256(key[:], []byte("__celeris_dummy_pw__"))
		cfg.Validator = func(user, pass string) bool {
			e, ok := entries[user]
			passMAC := hmacSHA256(key[:], []byte(pass))
			if !ok {
				// The comparison result is assigned to _ to document intent.
				// In Go, function calls with side effects cannot be elided by
				// the compiler, so the timing behavior is preserved regardless.
				_ = subtle.ConstantTimeCompare(passMAC, dummyMAC)
				return false
			}
			storedMAC := hmacSHA256(key[:], e.passBytes)
			return subtle.ConstantTimeCompare(passMAC, storedMAC) == 1
		}
	}
	if cfg.Validator == nil && cfg.ValidatorWithContext == nil && len(cfg.HashedUsers) > 0 {
		// Deep-copy and decode hex hashes at init time.
		type hashedEntry struct{ hashBytes [sha256.Size]byte }
		entries := make(map[string]hashedEntry, len(cfg.HashedUsers))
		for u, h := range cfg.HashedUsers {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != sha256.Size {
				panic("basicauth: HashedUsers[" + u + "]: invalid hex-encoded SHA-256 hash")
			}
			var entry hashedEntry
			copy(entry.hashBytes[:], b)
			entries[u] = entry
		}
		// Random dummy hash for unknown-user timing side-channel prevention.
		var dummyHash [sha256.Size]byte
		if _, err := rand.Read(dummyHash[:]); err != nil {
			panic("basicauth: crypto/rand failed: " + err.Error())
		}
		cfg.Validator = func(user, pass string) bool {
			e, ok := entries[user]
			passHash := sha256.Sum256([]byte(pass))
			if !ok {
				_ = subtle.ConstantTimeCompare(passHash[:], dummyHash[:])
				return false
			}
			return subtle.ConstantTimeCompare(passHash[:], e.hashBytes[:]) == 1
		}
	}
	return cfg
}

// hmacSHA256 computes HMAC-SHA256(key, data) and returns the 32-byte tag.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// HashPassword returns the hex-encoded SHA-256 hash of password.
// Use this to produce values for [Config].HashedUsers.
func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func (cfg Config) validate() {
	if cfg.Validator == nil && cfg.ValidatorWithContext == nil {
		panic("basicauth: Validator, ValidatorWithContext, Users, or HashedUsers is required")
	}
}
