package bodylimit

import "github.com/goceleris/celeris"

// Config defines the body limit middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// MaxBytes is the maximum allowed request body size in bytes.
	// Default: 4 MB (4 * 1024 * 1024).
	MaxBytes int64
}

// DefaultConfig is the default body limit configuration.
var DefaultConfig = Config{
	MaxBytes: 4 * 1024 * 1024, // 4 MB
}

func applyDefaults(cfg Config) Config {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultConfig.MaxBytes
	}
	return cfg
}

func (cfg Config) validate() {}
