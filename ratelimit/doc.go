// Package ratelimit provides token-bucket rate limiting middleware for
// celeris.
//
// The limiter uses a sharded token-bucket algorithm keyed by client IP
// (by default). Each key gets an independent bucket that refills at the
// configured requests-per-second rate up to the burst capacity. A
// background goroutine periodically evicts expired buckets.
//
// Basic usage with defaults (10 RPS, burst 20):
//
//	server.Use(ratelimit.New())
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
// X-RateLimit-Reset headers on every response. When the limit is
// exceeded it returns 429 Too Many Requests.
package ratelimit
