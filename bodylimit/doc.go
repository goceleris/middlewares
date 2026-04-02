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
// [Config].Limit accepts human-readable size strings with decimal (SI-style)
// and binary (IEC) units: B, KB, MB, GB, TB, PB, EB, KiB, MiB, GiB, TiB,
// PiB, EiB (e.g., "1.5GB", "256MiB"). Fractional values are supported.
// When set, Limit takes precedence over MaxBytes.
//
// # Dual-Check Enforcement
//
// The middleware uses a two-phase approach to enforce body size limits:
//
//  1. Content-Length pre-check: If the request includes a Content-Length
//     header and its value exceeds the configured limit, the request is
//     rejected immediately without reading any body bytes. This provides
//     an efficient fast path for well-behaved clients that advertise
//     their payload size up front.
//
//  2. Actual body byte count fallback: Regardless of the Content-Length
//     header, the middleware also checks the actual number of body bytes
//     received. This catches clients that send a small or missing
//     Content-Length but transmit a larger payload (a "lying"
//     Content-Length) as well as chunked-transfer requests that omit the
//     header entirely.
//
// Both checks must pass for the request to proceed. This defense-in-depth
// approach ensures that the limit is enforced even when the
// Content-Length header is absent, zero, or deliberately understated.
//
// # Streaming Limitation
//
// Celeris buffers the full request body before middleware executes. This
// means oversized payloads without a Content-Length header will be buffered
// into memory before this middleware can reject them. The framework's own
// maxRequestBodySize (100 MB) provides the hard ceiling that prevents
// unbounded memory growth.
//
// For strict enforcement, enable [Config].ContentLengthRequired to reject
// requests that omit the Content-Length header with 411 Length Required,
// forcing clients to declare body size up front:
//
//	server.Use(bodylimit.New(bodylimit.Config{
//	    Limit:                 "10MB",
//	    ContentLengthRequired: true,
//	}))
//
// Bodyless HTTP methods (GET, HEAD, DELETE, OPTIONS) are auto-skipped
// since they never carry a request body, avoiding unnecessary overhead.
//
// # Custom Error Handling
//
// Set [Config].ErrorHandler to customize the response when the body limit
// is exceeded:
//
//	server.Use(bodylimit.New(bodylimit.Config{
//	    Limit: "10MB",
//	    ErrorHandler: func(c *celeris.Context, err error) error {
//	        return c.JSON(413, map[string]string{"error": "body too large"})
//	    },
//	}))
//
// # Skipping
//
// Use [Config].Skip for dynamic skip logic or [Config].SkipPaths for
// exact-match path exclusions (e.g., health check endpoints).
//
// [ErrBodyTooLarge] is the exported sentinel error (413) returned when the
// limit is exceeded, usable with errors.Is for error handling in upstream
// middleware. [ErrLengthRequired] is the sentinel error (411) returned when
// [Config].ContentLengthRequired is enabled and the request omits a
// Content-Length header.
package bodylimit
