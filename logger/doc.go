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
// Using the zero-alloc FastHandler for high-throughput servers:
//
//	mw := logger.New(logger.Config{
//	    Output: slog.New(logger.NewFastHandler(os.Stderr, nil)),
//	})
//	server.Use(mw)
//
// [NewFastHandler] creates a [FastHandler] that formats log records
// directly into a pooled byte buffer, producing output compatible with
// slog.TextHandler. Configure its minimum level via [FastHandlerOptions].
//
// The middleware automatically includes client_ip, request_id (from the
// x-request-id header), and error fields when present. Additional fields
// can be added via [Config].Fields.
package logger
