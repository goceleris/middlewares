// Package bodylimit provides request body size limiting middleware for
// celeris.
//
// The middleware enforces a maximum request body size. Requests whose
// Content-Length header exceeds the limit are rejected immediately with
// 413 Request Entity Too Large. Requests without Content-Length are
// rejected once the actual body bytes read exceed the limit.
//
// Basic usage with the default 4 MB limit:
//
//	server.Use(bodylimit.New())
//
// Human-readable size string:
//
//	server.Use(bodylimit.New(bodylimit.Config{
//	    Limit: "10MB",
//	}))
//
// Numeric byte limit:
//
//	server.Use(bodylimit.New(bodylimit.Config{
//	    MaxBytes: 10 * 1024 * 1024, // 10 MB
//	}))
//
// [Config].Limit accepts human-readable size strings with units B, KB, MB,
// GB, and TB (e.g., "1.5GB"). When set, it takes precedence over MaxBytes.
//
// [ErrBodyTooLarge] is the exported sentinel error (413) returned when the
// limit is exceeded, usable with errors.Is for error handling in upstream
// middleware.
package bodylimit
