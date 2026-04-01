package ratelimit

import (
	"time"

	"github.com/goceleris/celeris"
)

var errTooManyRequests = celeris.NewHTTPError(429, "Too Many Requests")

// New creates a rate limit middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	limiter := newShardedLimiter(cfg.Shards, cfg.RPS, cfg.Burst, cfg.CleanupInterval, cfg.CleanupContext)
	keyFunc := cfg.KeyFunc
	limitStr := formatInt(cfg.Burst)

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		key := keyFunc(c)
		now := time.Now().UnixNano()
		allowed, remaining, resetNano := limiter.allow(key, now)

		c.SetHeader("x-ratelimit-limit", limitStr)
		c.SetHeader("x-ratelimit-remaining", formatInt(remaining))
		c.SetHeader("x-ratelimit-reset", formatResetSeconds(resetNano, now))

		if !allowed {
			return errTooManyRequests
		}

		return c.Next()
	}
}
