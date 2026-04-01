// Package recovery provides panic recovery middleware for celeris.
//
// The middleware catches panics from downstream handlers, logs the
// stack trace via slog, and returns a configurable error response
// instead of crashing the server.
//
// Basic usage with defaults (4 KB stack trace, JSON 500 response):
//
//	server.Use(recovery.New())
//
// Custom error handler and stack size:
//
//	server.Use(recovery.New(recovery.Config{
//	    StackSize: 8192,
//	    ErrorHandler: func(c *celeris.Context, err any) error {
//	        return c.String(500, "Something went wrong")
//	    },
//	}))
//
// Set [Config].StackSize to 0 to disable stack trace capture.
// Set [Config].LogStack to false to suppress panic logging entirely.
package recovery
