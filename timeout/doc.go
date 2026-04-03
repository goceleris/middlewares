// Package timeout provides request timeout middleware for celeris.
//
// The middleware wraps each request's context with a deadline. If the
// downstream handler does not complete before the deadline, the context
// is cancelled and a configurable error response is returned.
//
// Basic usage with the default 5-second timeout:
//
//	server.Use(timeout.New())
//
// Custom timeout and error handler:
//
//	server.Use(timeout.New(timeout.Config{
//	    Timeout: 10 * time.Second,
//	    ErrorHandler: func(c *celeris.Context) error {
//	        return c.JSON(503, map[string]string{"error": "timed out"})
//	    },
//	}))
//
// # Preemptive Mode
//
// Set [Config].Preemptive to true to run the handler in a separate
// goroutine with response buffering. In preemptive mode, the middleware
// returns the timeout error immediately when the deadline expires, even
// if the handler is blocked on a non-context-aware operation. Panics in
// the preemptive goroutine are recovered automatically.
//
//	server.Use(timeout.New(timeout.Config{
//	    Timeout:    5 * time.Second,
//	    Preemptive: true,
//	}))
//
// # Per-Request Timeout
//
// Set [Config].TimeoutFunc to compute a timeout dynamically per request.
// The static [Config].Timeout is used as a fallback when TimeoutFunc is
// nil or returns a non-positive duration.
//
//	server.Use(timeout.New(timeout.Config{
//	    Timeout: 5 * time.Second,
//	    TimeoutFunc: func(c *celeris.Context) time.Duration {
//	        if c.Path() == "/upload" {
//	            return 30 * time.Second
//	        }
//	        return 0 // fall back to static Timeout
//	    },
//	}))
//
// # Cooperative vs Preemptive Tradeoffs
//
// In cooperative mode (default), the handler runs in the request
// goroutine. The context deadline is set, but the handler must check
// c.Context().Done() or use context-aware I/O to respect the timeout.
// If the handler blocks on a non-context-aware call (e.g., a raw
// syscall), the timeout fires after the handler returns. Cooperative
// mode has no extra goroutine overhead and no response buffering cost.
//
// In preemptive mode, the handler runs in a separate goroutine and
// the response is buffered. When the deadline expires, the middleware
// immediately returns the timeout error even if the handler is still
// blocked. The tradeoff is one extra goroutine per request plus memory
// for response buffering. Panics in the handler goroutine are recovered
// automatically.
//
// Handlers MUST check c.Context().Done() to react promptly to
// cancellation in both modes.
//
// In preemptive mode, the done-signal channels are pooled via sync.Pool
// to avoid allocating a new channel per request.
//
// # Error Handling
//
// [ErrServiceUnavailable] is the exported sentinel error (*celeris.HTTPError
// with code 503) returned when a request times out and no custom error
// handler is configured. Upstream middleware can match it with errors.Is:
//
//	var he *celeris.HTTPError
//	if errors.As(err, &he) && he.Code == 503 { ... }
//
// To customize the timeout response, set [Config].ErrorHandler. To inspect
// the failure reason (deadline exceeded, matched TimeoutErrors entry, or
// recovered panic), set [Config].ErrorHandlerWithError instead — it takes
// precedence over ErrorHandler when both are set:
//
//	server.Use(timeout.New(timeout.Config{
//	    Timeout: 5 * time.Second,
//	    ErrorHandlerWithError: func(c *celeris.Context, err error) error {
//	        log.Printf("timeout cause: %v", err)
//	        return c.JSON(503, map[string]string{"error": "timed out"})
//	    },
//	}))
//
// If the error handler itself panics, the middleware recovers and returns
// [ErrServiceUnavailable] as a last-resort fallback.
//
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
package timeout
