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
// [ParseRate] parses rate strings in "<count>-<unit>" format into RPS and
// burst values. The count becomes the burst capacity. Supported units:
// S (second), M (minute), H (hour), D (day). Examples: "5-S" (5 req/s,
// burst 5), "100-M" (100 req/min, burst 100), "1000-H" (1000 req/hr,
// burst 1000).
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
// # Sharded Architecture
//
// The limiter partitions buckets across multiple lock shards to reduce
// contention under high concurrency. [Config].Shards controls the number
// of shards (rounded up to the next power of 2); the default is
// [runtime.NumCPU]. Each shard is an independent map guarded by its own
// mutex, so concurrent requests to different keys rarely contend on the
// same lock.
//
// # Response Headers
//
// The middleware sets three standard rate limit headers on every allowed
// response:
//
//   - X-RateLimit-Limit: the burst capacity (maximum tokens).
//   - X-RateLimit-Remaining: tokens left after this request.
//   - X-RateLimit-Reset: seconds until the bucket next gains a token
//     (ceiling-rounded to whole seconds, minimum 1 per RFC 7231 §7.1.3).
//
// Set [Config].DisableHeaders to true to suppress all rate limit headers,
// including Retry-After on denied responses. This is useful for internal
// services where header overhead is unwanted, or when a reverse proxy
// injects its own rate limit headers.
//
// # Retry-After Header
//
// When a request is denied (429 Too Many Requests), the middleware adds a
// Retry-After header whose value is the number of whole seconds the client
// should wait before retrying (RFC 7231 §7.1.3). The value is computed as
// the ceiling of the time until the bucket accumulates one full token at
// the configured refill rate. Clients that respect Retry-After avoid
// wasting bandwidth on requests that will be rejected.
//
// The Retry-After header is set before [Config].LimitReached is called, so
// custom deny handlers can read or override it via c.SetHeader.
//
// # Deny Hook
//
// [Config].LimitReached is called when a request is rate-limited, allowing
// custom deny responses or side effects (logging, metrics).
//
// [ErrTooManyRequests] is the exported sentinel error (429) returned on
// deny, usable with errors.Is for error handling in upstream middleware.
//
// # NTP Clock-Step Protection
//
// The token bucket tracks time via nanosecond timestamps. If the system
// clock jumps backward (e.g., an NTP step correction), the elapsed
// duration since the last refill would be negative, which could award
// negative tokens and lock out the key. To prevent this, the limiter
// clamps negative elapsed durations to zero: a backward step is treated
// as if no time has passed, so existing tokens are preserved and the
// bucket resumes normal refill from the new timestamp. Forward steps
// are handled naturally — the bucket fills to its burst cap and any
// excess is discarded.
//
// # Sliding Window
//
// When [Config].SlidingWindow is true, the middleware uses a sliding window
// counter instead of the default token bucket. The sliding window tracks
// the previous and current window counts, weighted by the elapsed fraction
// of the current window, providing smoother rate limiting near window
// boundaries.
//
// Caveat: under concurrent load near a window boundary, an undo (from
// SkipFailedRequests/SkipSuccessfulRequests) may restore a count into a
// window that has already advanced, slightly skewing the weighted estimate.
// This is inherent to the sliding-window-counter algorithm and acceptable
// for rate limiting purposes.
//
// # Dynamic Rate Limiting
//
// [Config].RateFunc allows per-request rate selection. The number of
// distinct rate strings is capped by [Config].MaxDynamicLimiters (default
// 1024). When exceeded, the middleware returns an error rather than
// allowing unbounded memory growth. Each dynamic limiter's cleanup
// goroutine is tied to the parent [Config].CleanupContext and stops when
// that context is cancelled.
//
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
package ratelimit
