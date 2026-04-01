package basicauth

import (
	"crypto/subtle"

	"github.com/goceleris/celeris"
)

// UsernameKey is the context store key for the authenticated username.
const UsernameKey = "basicauth_username"

// Config defines the basic auth middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Validator checks credentials. Required if Users is nil -- panics if both are nil.
	Validator func(user, pass string) bool

	// ValidatorWithContext checks credentials with access to the request context.
	// Takes precedence over Validator when set. Useful for per-request auth decisions
	// (e.g., tenant-based authentication, IP-aware rate limiting within auth).
	ValidatorWithContext func(c *celeris.Context, user, pass string) bool

	// Users maps usernames to passwords. When set and Validator is nil,
	// a constant-time validator is auto-generated from this map.
	Users map[string]string

	// Realm is the authentication realm. Default: "Restricted".
	Realm string

	// ErrorHandler handles authentication failures.
	// Default: 401 with WWW-Authenticate header.
	ErrorHandler func(c *celeris.Context) error

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string
}

// DefaultConfig is the default basic auth configuration.
var DefaultConfig = Config{
	Realm: "Restricted",
}

func applyDefaults(cfg Config) Config {
	if cfg.Realm == "" {
		cfg.Realm = DefaultConfig.Realm
	}
	if cfg.Validator == nil && cfg.ValidatorWithContext == nil && len(cfg.Users) > 0 {
		// Deep-copy the map so post-New() mutations don't affect the validator.
		type userEntry struct{ passBytes []byte }
		entries := make(map[string]userEntry, len(cfg.Users))
		// dummy is a fixed-length value used for unknown-user comparisons
		// to prevent timing side-channels on username existence.
		dummy := []byte("__celeris_dummy_pw__")
		for u, p := range cfg.Users {
			entries[u] = userEntry{passBytes: []byte(p)}
		}
		cfg.Validator = func(user, pass string) bool {
			e, ok := entries[user]
			if !ok {
				subtle.ConstantTimeCompare([]byte(pass), dummy)
				return false
			}
			return subtle.ConstantTimeCompare([]byte(pass), e.passBytes) == 1
		}
	}
	return cfg
}

func (cfg Config) validate() {
	if cfg.Validator == nil && cfg.ValidatorWithContext == nil {
		panic("basicauth: Validator, ValidatorWithContext, or Users is required")
	}
}
