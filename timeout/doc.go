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
// Handlers should select on c.Context().Done() to react promptly to
// cancellation.
package timeout
