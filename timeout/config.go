package timeout

import (
	"time"

	"github.com/goceleris/celeris"
)

// Config defines the timeout middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Timeout is the request timeout duration. Default: 5s.
	Timeout time.Duration

	// ErrorHandler handles timeout errors. Default: 503 Service Unavailable.
	ErrorHandler func(c *celeris.Context) error

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string
}

// DefaultConfig is the default timeout configuration.
var DefaultConfig = Config{
	Timeout: 5 * time.Second,
}

func applyDefaults(cfg Config) Config {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultConfig.Timeout
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}
	return cfg
}

var errServiceUnavailable = celeris.NewHTTPError(503, "Service Unavailable")

func defaultErrorHandler(_ *celeris.Context) error {
	return errServiceUnavailable
}

func (cfg Config) validate() {}
