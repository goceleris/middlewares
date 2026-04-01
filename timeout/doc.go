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
// Handlers MUST check c.Context().Done() to react promptly to
// cancellation, especially in non-preemptive mode.
//
// [ErrServiceUnavailable] is the exported sentinel error (503) returned
// on timeout, usable with errors.Is for error handling in upstream
// middleware.
package timeout
