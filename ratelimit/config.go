package ratelimit

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/goceleris/celeris"
)

// Store defines the interface for pluggable rate limit storage backends
// (e.g., Redis). The store handles its own rate/burst logic; Config.RPS
// and Config.Burst are ignored when Store is set.
type Store interface {
	// Allow checks if the request identified by key is allowed.
	// Returns whether the request is allowed, the remaining token count,
	// and the time at which the bucket resets.
	Allow(key string) (allowed bool, remaining int, resetAt time.Time, err error)
}

// StoreUndo is an optional interface that Store implementations may
// satisfy to support token refunds. Used by SkipFailedRequests and
// SkipSuccessfulRequests.
type StoreUndo interface {
	Undo(key string) error
}

// Config defines the rate limit middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Store, when set, replaces the built-in sharded limiter with an
	// external storage backend (e.g., Redis). The store is responsible
	// for its own rate and burst logic; RPS, Burst, Shards, and
	// CleanupInterval are ignored.
	Store Store

	// RPS is the refill rate in requests per second per key. Default: 10.
	RPS float64

	// Burst is the maximum tokens (burst capacity). Default: 20.
	Burst int

	// Rate is a human-readable rate string (e.g., "100-M" for 100 per minute).
	// Supported units: S (second), M (minute), H (hour), D (day).
	// Takes precedence over RPS/Burst when set. If Burst is also set
	// explicitly, the user's Burst is preserved (Rate only overrides RPS).
	Rate string

	// RateFunc, when set, is called per-request to determine the rate.
	// Returns a rate string in the same format as Rate (e.g., "100-M").
	// Falls back to the static Rate/RPS/Burst when it returns an empty string.
	// Parsed via ParseRate.
	RateFunc func(c *celeris.Context) (rate string, err error)

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

	// DisableHeaders disables X-RateLimit-* response headers.
	DisableHeaders bool

	// SlidingWindow, when true, uses a sliding window counter instead
	// of the default token bucket algorithm. The sliding window tracks
	// the previous and current window counts, weighted by the elapsed
	// fraction of the current window. This provides smoother rate limiting
	// near window boundaries.
	SlidingWindow bool

	// SkipFailedRequests, when true, refunds the token for requests
	// whose downstream handler returns a status >= 400. The token is
	// refunded after c.Next() completes.
	SkipFailedRequests bool

	// SkipSuccessfulRequests, when true, refunds the token for requests
	// whose downstream handler returns a status < 400. The token is
	// refunded after c.Next() completes.
	SkipSuccessfulRequests bool

	// LimitReached is called when a request is rate-limited.
	// If nil, returns 429 Too Many Requests.
	LimitReached func(c *celeris.Context) error

	// MaxDynamicLimiters caps the number of distinct rate strings cached
	// when RateFunc is used. When exceeded, new rate strings are rejected
	// with an error. Default: 1024.
	MaxDynamicLimiters int
}

// DefaultConfig is the default rate limit configuration.
var DefaultConfig = Config{
	RPS:             10,
	Burst:           20,
	Shards:          runtime.NumCPU(),
	CleanupInterval: time.Minute,
}

func applyDefaults(cfg Config) Config {
	if cfg.Rate != "" {
		rps, burst := ParseRate(cfg.Rate)
		cfg.RPS = rps
		// Only override Burst if the user did not set it explicitly (issue #10).
		if cfg.Burst <= 0 {
			cfg.Burst = burst
		}
	}
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
	if cfg.MaxDynamicLimiters <= 0 {
		cfg.MaxDynamicLimiters = 1024
	}
	return cfg
}

func (cfg Config) validate() {
	if cfg.Burst < 1 {
		panic("ratelimit: Burst must be >= 1")
	}
}

// ParseRate parses a human-readable rate string into RPS and burst values.
// Format: "<count>-<unit>" where unit is S (second), M (minute), H (hour), D (day).
// Examples: "100-M" (100 per minute), "1000-H" (1000 per hour), "5-S" (5 per second).
// The burst is set equal to the count.
func ParseRate(s string) (rps float64, burst int) {
	s = strings.TrimSpace(s)
	idx := strings.LastIndexByte(s, '-')
	if idx < 1 || idx >= len(s)-1 {
		panic("ratelimit: invalid Rate format (use <count>-<unit>, e.g. \"100-M\"): " + s)
	}
	countStr := strings.TrimSpace(s[:idx])
	unit := strings.ToUpper(strings.TrimSpace(s[idx+1:]))

	count, err := strconv.ParseFloat(countStr, 64)
	if err != nil || count <= 0 {
		panic("ratelimit: invalid Rate count: " + s)
	}

	var seconds float64
	switch unit {
	case "S":
		seconds = 1
	case "M":
		seconds = 60
	case "H":
		seconds = 3600
	case "D":
		seconds = 86400
	default:
		panic("ratelimit: invalid Rate unit (use S, M, H, or D): " + s)
	}

	return count / seconds, int(count)
}
