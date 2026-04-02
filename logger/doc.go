// Package logger provides HTTP request logging middleware for celeris.
//
// The middleware logs each request with configurable fields including
// method, path, status, latency, and bytes written. It supports
// both standard slog handlers and the zero-alloc [FastHandler].
//
// Basic usage with the default slog output:
//
//	server.Use(logger.New())
//
// Using the zero-alloc FastHandler with color output:
//
//	mw := logger.New(logger.Config{
//	    Output: slog.New(logger.NewFastHandler(os.Stderr, &logger.FastHandlerOptions{
//	        Color: true,
//	    })),
//	})
//	server.Use(mw)
//
// [NewFastHandler] creates a [FastHandler] that formats log records
// directly into a pooled byte buffer, producing output compatible with
// slog.TextHandler. When [FastHandlerOptions].Color is true, status codes,
// HTTP methods, and latency values are colored with ANSI escape codes
// (e.g., green for 2xx, red for 5xx). Configure its minimum level via
// [FastHandlerOptions].
//
// # Body Capture
//
// Set [Config].CaptureRequestBody and/or [Config].CaptureResponseBody to
// log request and response bodies. Bodies are truncated to
// [Config].MaxCaptureBytes (default 4096).
//
//	server.Use(logger.New(logger.Config{
//	    CaptureRequestBody:  true,
//	    CaptureResponseBody: true,
//	    MaxCaptureBytes:     2048,
//	}))
//
// # Sensitive Header Redaction
//
// [Config].SensitiveHeaders lists header names whose values should be
// redacted in log output. Values are replaced with "[REDACTED]". Header
// names are matched case-insensitively. Use this to prevent credentials,
// tokens, or other secrets from appearing in logs:
//
//	server.Use(logger.New(logger.Config{
//	    SensitiveHeaders: []string{"Authorization", "Cookie"},
//	}))
//
// # Request ID Integration
//
// The middleware automatically reads the request ID from the context store
// (key "request_id") first, falling back to the x-request-id header.
// This integrates seamlessly with the requestid middleware when both are
// installed. Additional fields can be added via [Config].Fields.
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
//
// # Performance
//
// [FastHandler] formats log records directly into a pooled byte buffer,
// avoiding fmt.Sprintf and time.Format entirely. Timestamps are rendered
// with a hand-rolled RFC 3339 formatter, and integer/duration/bool values
// use strconv.Append* functions. The default configuration with no opt-in
// fields (LogHost, LogUserAgent, etc.) achieves zero heap allocations per
// request in steady state.
package logger
