// Package requestid provides request ID middleware for celeris.
//
// The middleware reads the request ID from the incoming X-Request-Id
// header (configurable). If the incoming ID is absent or invalid, a
// new UUID v4 is generated using a buffered random source that batches
// 256 UUIDs per crypto/rand syscall. The ID is set on both the response
// header and the context store under [ContextKey] ("request_id").
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
// # Input Validation
//
// Incoming IDs are validated: only printable ASCII (0x20-0x7E) is
// accepted, with a maximum length of 128 characters. Invalid or
// oversized IDs are silently replaced with a fresh UUID.
//
// # DisableTrustProxy (replaces TrustProxy)
//
// [Config].DisableTrustProxy controls whether the inbound request header
// is accepted. When false (default), a valid inbound header is propagated
// as-is. When true, the inbound header is always ignored and a fresh ID
// is generated. Set to true when running behind untrusted clients to
// prevent request ID spoofing:
//
//	server.Use(requestid.New(requestid.Config{
//	    DisableTrustProxy: true,
//	}))
//
// The old [Config].TrustProxy *bool field is retained as a deprecated
// backward-compatibility alias. When set to a non-nil value, it overrides
// DisableTrustProxy in applyDefaults (*TrustProxy==false maps to
// DisableTrustProxy=true and vice versa).
//
// # Retrieving the Request ID
//
// Use [FromContext] to retrieve the request ID from downstream handlers:
//
//	id := requestid.FromContext(c) // reads ContextKey from context store
//
// # Skipping
//
// Use [Config].Skip for dynamic skip logic or [Config].SkipPaths for
// path exclusions. SkipPaths uses exact matching after trimming trailing
// slashes from both the configured paths and the request path.
//
// # AfterGenerate
//
// [Config].AfterGenerate is called after the request ID is set. Panics
// in AfterGenerate are not recovered by this middleware and will
// propagate to the caller (or any upstream recovery middleware).
//
// # Custom Generator Validation
//
// Custom generator output is validated with the same rules as inbound
// headers (printable ASCII, max 128 characters). If the generator
// returns an invalid or empty string, it is retried up to 3 times
// before falling back to the built-in UUID generator.
//
// [CounterGenerator] returns a monotonic ID generator ("{prefix}-{N}")
// with zero syscalls after initialization.
package requestid
