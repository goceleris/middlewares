package bodylimit

import (
	"strconv"
	"strings"

	"github.com/goceleris/celeris"
)

// Config defines the body limit middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Limit is a human-readable size string (e.g., "10MB", "1.5GB").
	// Takes precedence over MaxBytes when set.
	Limit string

	// MaxBytes is the maximum allowed request body size in bytes.
	// Default: 4 MB (4 * 1024 * 1024).
	MaxBytes int64

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// ErrorHandler handles body-too-large errors. When non-nil, it is
	// called instead of returning ErrBodyTooLarge directly.
	ErrorHandler func(c *celeris.Context, err error) error
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

func validate(cfg *Config) {
	if cfg.Limit != "" {
		cfg.MaxBytes = parseSize(cfg.Limit)
	}
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		panic("bodylimit: empty Limit string")
	}

	type suffix struct {
		name string
		mult float64
	}
	suffixes := [...]suffix{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
		{"B", 1},
	}

	upper := strings.ToUpper(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, sf.name) {
			numStr := strings.TrimSpace(s[:len(s)-len(sf.name)])
			val, err := strconv.ParseFloat(numStr, 64)
			if err != nil || val < 0 {
				panic("bodylimit: invalid Limit: " + s)
			}
			n := int64(val * sf.mult)
			if n <= 0 {
				panic("bodylimit: Limit must be positive: " + s)
			}
			return n
		}
	}
	panic("bodylimit: invalid Limit format (use B, KB, MB, GB, TB): " + s)
}
