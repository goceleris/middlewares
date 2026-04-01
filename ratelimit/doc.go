// Package ratelimit provides token-bucket rate limiting middleware for
// celeris.
//
// The limiter uses a sharded token-bucket algorithm keyed by client IP
// (by default). Each key gets an independent bucket that refills at the
// configured rate up to the burst capacity. A background goroutine
// periodically evicts expired buckets.
//
// Basic usage with defaults (10 RPS, burst 20):
//
//	server.Use(ratelimit.New())
//
// Human-readable rate string (100 per minute, burst 200):
//
//	server.Use(ratelimit.New(ratelimit.Config{
//	    Rate:  "100-M",
//	    Burst: 200,
//	}))
//
// [ParseRate] parses rate strings into RPS and burst values. Supported
// units: S (second), M (minute), H (hour), D (day).
//
// Custom limits keyed by API key:
//
//	server.Use(ratelimit.New(ratelimit.Config{
//	    RPS:   100,
//	    Burst: 200,
//	    KeyFunc: func(c *celeris.Context) string {
//	        return c.Header("x-api-key")
//	    },
//	}))
//
// The middleware sets X-RateLimit-Limit, X-RateLimit-Remaining, and
// X-RateLimit-Reset headers on every response. Set [Config].DisableHeaders
// to true to suppress these headers. When the limit is exceeded, a
// Retry-After header is included in the 429 response.
//
// [Config].LimitReached is called when a request is rate-limited, allowing
// custom deny responses or side effects (logging, metrics).
//
// [ErrTooManyRequests] is the exported sentinel error (429) returned on
// deny, usable with errors.Is for error handling in upstream middleware.
//
// The token bucket uses monotonic time internally, clamping negative
// elapsed durations to zero to handle NTP clock step-backs gracefully.
package ratelimit
