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
// Set [Config].StackSize to 0 to disable stack trace capture (the panic
// value, method, and path are still logged; only the goroutine stack is
// omitted). Set [Config].DisableLogStack to true to suppress panic logging
// entirely.
//
// # DisableLogStack (replaces LogStack)
//
// The old [Config].LogStack field suffered from a zero-value problem:
// because Go's bool zero value is false, a partial Config literal such as
// recovery.Config{StackSize: 8192} silently disabled stack logging.
//
// [Config].DisableLogStack inverts the polarity so the zero value (false)
// means "stacks are logged" — the desired default. The old LogStack field
// is retained as a deprecated backward-compatibility alias: only
// LogStack: true has effect (it forces DisableLogStack to false in
// applyDefaults). LogStack: false is indistinguishable from "not set" due
// to Go's zero-value semantics and is ignored. To suppress stack logging,
// use DisableLogStack: true.
//
// # Special Panic Types
//
// Panics with [http.ErrAbortHandler] (matched via errors.Is) are re-panicked
// rather than recovered, preserving the standard library's abort semantics.
//
// Broken pipe and ECONNRESET errors are detected automatically and logged
// at WARN level without a stack trace, since the client has disconnected.
// Use [Config].BrokenPipeHandler to customize the response for these cases.
// Set [Config].DisableBrokenPipeLog to true to suppress the WARN log
// entirely (useful in environments where broken pipes are routine).
//
// # Nested Recovery
//
// If [Config].ErrorHandler itself panics, the middleware falls back to a
// default 500 Internal Server Error response.
//
// # Stack Options
//
// Set [Config].StackAll to true to capture stack traces for all goroutines,
// not just the current one. The method and path are included in the panic
// log output for easier debugging.
package recovery
