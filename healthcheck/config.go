package healthcheck

import (
	"time"

	"github.com/goceleris/celeris"
)

// Exported path constants for the default probe endpoints.
const (
	DefaultLivePath  = "/livez"
	DefaultReadyPath = "/readyz"
	DefaultStartPath = "/startupz"
)

// Checker reports a probe's health status. The context is provided so
// checkers can inspect the request or respect deadlines.
type Checker func(c *celeris.Context) bool

// Config defines the healthcheck middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// LivePath is the URL path for the liveness probe.
	// Default: "/livez".
	LivePath string

	// ReadyPath is the URL path for the readiness probe.
	// Default: "/readyz".
	ReadyPath string

	// StartPath is the URL path for the startup probe.
	// Default: "/startupz".
	StartPath string

	// LiveChecker reports whether the process is alive.
	// Default: always true.
	LiveChecker Checker

	// ReadyChecker reports whether the service can accept traffic.
	// Default: always true.
	ReadyChecker Checker

	// StartChecker reports whether initial startup has completed.
	// Default: always true.
	StartChecker Checker

	// CheckerTimeout is the maximum duration to wait for a checker to
	// complete. If the checker does not return within this duration,
	// the probe returns 503 unavailable. Default: 5s.
	CheckerTimeout time.Duration
}

// DefaultCheckerTimeout is the default timeout for health checkers.
const DefaultCheckerTimeout = 5 * time.Second

// DefaultConfig is the default healthcheck middleware configuration.
var DefaultConfig = Config{
	LivePath:       DefaultLivePath,
	ReadyPath:      DefaultReadyPath,
	StartPath:      DefaultStartPath,
	LiveChecker:    func(_ *celeris.Context) bool { return true },
	ReadyChecker:   func(_ *celeris.Context) bool { return true },
	StartChecker:   func(_ *celeris.Context) bool { return true },
	CheckerTimeout: DefaultCheckerTimeout,
}

func applyDefaults(cfg Config) Config {
	if cfg.LivePath == "" {
		cfg.LivePath = DefaultConfig.LivePath
	}
	if cfg.ReadyPath == "" {
		cfg.ReadyPath = DefaultConfig.ReadyPath
	}
	if cfg.StartPath == "" {
		cfg.StartPath = DefaultConfig.StartPath
	}
	if cfg.LiveChecker == nil {
		cfg.LiveChecker = DefaultConfig.LiveChecker
	}
	if cfg.ReadyChecker == nil {
		cfg.ReadyChecker = DefaultConfig.ReadyChecker
	}
	if cfg.StartChecker == nil {
		cfg.StartChecker = DefaultConfig.StartChecker
	}
	if cfg.CheckerTimeout <= 0 {
		cfg.CheckerTimeout = DefaultCheckerTimeout
	}
	return cfg
}

func (cfg Config) validate() {}
