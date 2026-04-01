// Package requestid provides request ID middleware for celeris.
//
// The middleware reads the request ID from the incoming X-Request-Id
// header (configurable). If absent, it generates a new UUID v4 using a
// buffered random source that batches 256 UUIDs per crypto/rand syscall.
// The ID is set on both the response header and the context store
// (key "request_id").
//
// Basic usage:
//
//	server.Use(requestid.New())
//
// Custom header and deterministic generator for testing:
//
//	server.Use(requestid.New(requestid.Config{
//	    Header:    "x-trace-id",
//	    Generator: requestid.CounterGenerator("req"),
//	}))
//
// [CounterGenerator] returns a monotonic ID generator ("{prefix}-{N}")
// with zero syscalls after initialization.
package requestid
