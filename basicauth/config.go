package basicauth

import "github.com/goceleris/celeris"

// Config defines the basic auth middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Validator checks credentials. Required -- panics if nil.
	Validator func(user, pass string) bool

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
	return cfg
}

func (cfg Config) validate() {
	if cfg.Validator == nil {
		panic("basicauth: Validator is required")
	}
}
