package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

// ErrTooManyRequests is returned when the rate limit is exceeded.
var ErrTooManyRequests = celeris.NewHTTPError(429, "Too Many Requests")

// ErrDynamicLimitersExhausted is returned when the dynamic limiter map
// has reached MaxDynamicLimiters and a new rate string is requested.
var ErrDynamicLimitersExhausted = errors.New("ratelimit: dynamic limiter map full")

// limiter is an interface that both shardedLimiter and slidingWindowLimiter satisfy.
type limiter interface {
	allow(key string, now int64) (bool, int, int64)
	undo(key string)
}

// stoppableLimiter wraps a limiter with a cancel function so its cleanup
// goroutine can be stopped when the entry is evicted from the dynamic map.
type stoppableLimiter struct {
	lim    limiter
	burst  int
	cancel context.CancelFunc
}

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

	keyFunc := cfg.KeyFunc
	disableHeaders := cfg.DisableHeaders
	limitReached := cfg.LimitReached
	skipFailed := cfg.SkipFailedRequests
	skipSuccess := cfg.SkipSuccessfulRequests
	rateFunc := cfg.RateFunc

	if cfg.Store != nil {
		return newStoreMiddleware(cfg.Store, cfg.Skip, keyFunc, skipMap, disableHeaders, limitReached, skipFailed, skipSuccess)
	}

	var lim limiter
	if cfg.SlidingWindow {
		lim = newSlidingWindowLimiter(cfg.CleanupContext, cfg.Shards, cfg.RPS, cfg.Burst, cfg.CleanupInterval)
	} else {
		lim = newShardedLimiter(cfg.CleanupContext, cfg.Shards, cfg.RPS, cfg.Burst, cfg.CleanupInterval)
	}
	limitStr := formatInt(cfg.Burst)
	defaultBurst := cfg.Burst
	maxDynamic := cfg.MaxDynamicLimiters
	slidingWindow := cfg.SlidingWindow
	shards := cfg.Shards
	cleanupInterval := cfg.CleanupInterval

	// Parent context for dynamic limiter cleanup goroutines.
	parentCtx := cfg.CleanupContext
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	var (
		dynamicMu       sync.Mutex
		dynamicLimiters = make(map[string]stoppableLimiter)
	)

	getDynamicLimiter := func(rateStr string) (limiter, int, error) {
		dynamicMu.Lock()
		defer dynamicMu.Unlock()
		if e, ok := dynamicLimiters[rateStr]; ok {
			return e.lim, e.burst, nil
		}
		// Reject new entries when map is at capacity (issue #1).
		if len(dynamicLimiters) >= maxDynamic {
			return nil, 0, ErrDynamicLimitersExhausted
		}
		// Recover from ParseRate panics caused by invalid RateFunc output (issue #9).
		var rps float64
		var burst int
		var parseErr error
		func() {
			defer func() {
				if r := recover(); r != nil {
					parseErr = fmt.Errorf("%v", r)
				}
			}()
			rps, burst = ParseRate(rateStr)
		}()
		if parseErr != nil {
			return nil, 0, fmt.Errorf("invalid rate string from RateFunc: %w", parseErr)
		}
		// Create a child context so the cleanup goroutine can be stopped
		// when the entry is evicted or CleanupContext is cancelled (issue #2).
		childCtx, cancel := context.WithCancel(parentCtx)
		var dl limiter
		if slidingWindow {
			dl = newSlidingWindowLimiter(childCtx, shards, rps, burst, cleanupInterval)
		} else {
			dl = newShardedLimiter(childCtx, shards, rps, burst, cleanupInterval)
		}
		dynamicLimiters[rateStr] = stoppableLimiter{lim: dl, burst: burst, cancel: cancel}
		return dl, burst, nil
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		key := keyFunc(c)

		activeLim := lim
		activeBurst := defaultBurst

		if rateFunc != nil {
			rateStr, err := rateFunc(c)
			if err != nil {
				return fmt.Errorf("ratelimit: RateFunc error: %w", err)
			}
			if rateStr != "" {
				var dynErr error
				activeLim, activeBurst, dynErr = getDynamicLimiter(rateStr)
				if dynErr != nil {
					return fmt.Errorf("ratelimit: %w", dynErr)
				}
			}
		}

		now := time.Now().UnixNano()
		allowed, remaining, resetNano := activeLim.allow(key, now)

		activeLimitStr := limitStr
		if activeBurst != defaultBurst {
			activeLimitStr = formatInt(activeBurst)
		}

		if !disableHeaders {
			c.SetHeader("x-ratelimit-limit", activeLimitStr)
			c.SetHeader("x-ratelimit-remaining", formatInt(remaining))
			c.SetHeader("x-ratelimit-reset", formatResetSeconds(resetNano, now))
		}

		if !allowed {
			if !disableHeaders {
				c.SetHeader("retry-after", formatResetSeconds(resetNano, now))
			}
			if limitReached != nil {
				return limitReached(c)
			}
			return ErrTooManyRequests
		}

		err := c.Next()

		if skipFailed || skipSuccess {
			status := responseStatus(c, err)
			if (skipFailed && status >= 400) || (skipSuccess && status < 400) {
				activeLim.undo(key)
			}
		}

		return err
	}
}

func newStoreMiddleware(
	store Store,
	skipFunc func(c *celeris.Context) bool,
	keyFunc func(c *celeris.Context) string,
	skipMap map[string]struct{},
	disableHeaders bool,
	limitReached func(c *celeris.Context) error,
	skipFailed, skipSuccess bool,
) celeris.HandlerFunc {
	undoer, _ := store.(StoreUndo)

	return func(c *celeris.Context) error {
		if skipFunc != nil && skipFunc(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		key := keyFunc(c)
		allowed, remaining, resetAt, err := store.Allow(key)
		if err != nil {
			return fmt.Errorf("ratelimit: store error: %w", err)
		}

		if !disableHeaders {
			c.SetHeader("x-ratelimit-remaining", formatInt(remaining))
			resetSec := int(time.Until(resetAt).Seconds() + 0.999)
			if resetSec < 0 {
				resetSec = 0
			}
			c.SetHeader("x-ratelimit-reset", formatInt(resetSec))
		}

		if !allowed {
			if !disableHeaders {
				retryAfter := int(time.Until(resetAt).Seconds() + 0.999)
				if retryAfter < 0 {
					retryAfter = 0
				}
				c.SetHeader("retry-after", formatInt(retryAfter))
			}
			if limitReached != nil {
				return limitReached(c)
			}
			return ErrTooManyRequests
		}

		nextErr := c.Next()

		if (skipFailed || skipSuccess) && undoer != nil {
			status := responseStatus(c, nextErr)
			if (skipFailed && status >= 400) || (skipSuccess && status < 400) {
				_ = undoer.Undo(key)
			}
		}

		return nextErr
	}
}

// responseStatus derives the HTTP status code from the error or context.
// The error takes precedence: if the handler returned an HTTPError, its
// code is used. Otherwise the status written to the context is used.
func responseStatus(c *celeris.Context, err error) int {
	if err != nil {
		var he *celeris.HTTPError
		if errors.As(err, &he) {
			return he.Code
		}
		return 500
	}
	if status := c.StatusCode(); status != 0 {
		return status
	}
	return 200
}
