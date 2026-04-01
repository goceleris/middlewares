package ratelimit

import (
	"context"
	"runtime"
	"time"

	"github.com/goceleris/celeris"
)

// Config defines the rate limit middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// RPS is the refill rate in requests per second per key. Default: 10.
	RPS float64

	// Burst is the maximum tokens (burst capacity). Default: 20.
	Burst int

	// KeyFunc extracts the rate limit key from the request. Default: c.ClientIP().
	KeyFunc func(c *celeris.Context) string

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// Shards is the number of lock shards. Default: runtime.NumCPU().
	// Rounded up to the next power of 2.
	Shards int

	// CleanupInterval is how often expired buckets are cleaned. Default: 1 minute.
	CleanupInterval time.Duration

	// CleanupContext, if set, controls cleanup goroutine lifetime.
	// When the context is cancelled, the cleanup goroutine stops.
	// If nil, cleanup runs until the process exits.
	CleanupContext context.Context
}

// DefaultConfig is the default rate limit configuration.
var DefaultConfig = Config{
	RPS:             10,
	Burst:           20,
	Shards:          runtime.NumCPU(),
	CleanupInterval: time.Minute,
}

func applyDefaults(cfg Config) Config {
	if cfg.RPS <= 0 {
		cfg.RPS = DefaultConfig.RPS
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultConfig.Burst
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = func(c *celeris.Context) string {
			return c.ClientIP()
		}
	}
	if cfg.Shards <= 0 {
		cfg.Shards = DefaultConfig.Shards
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = DefaultConfig.CleanupInterval
	}
	return cfg
}

func (cfg Config) validate() {
	if cfg.Burst < 1 {
		panic("ratelimit: Burst must be >= 1")
	}
}
