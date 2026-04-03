// Package healthcheck provides Kubernetes-style health probe middleware
// for celeris.
//
// The middleware intercepts requests matching configurable probe paths
// (default "/livez", "/readyz", "/startupz") and returns a JSON status
// response based on checker functions. Requests that do not match any
// probe path are passed through to the next handler with zero overhead
// beyond string equality checks.
//
// Basic usage with defaults (all probes return 200):
//
//	server.Use(healthcheck.New())
//
// Custom readiness check:
//
//	server.Use(healthcheck.New(healthcheck.Config{
//	    ReadyChecker: func(_ *celeris.Context) bool {
//	        return db.Ping() == nil
//	    },
//	}))
//
// Custom paths:
//
//	server.Use(healthcheck.New(healthcheck.Config{
//	    LivePath:  "/health/live",
//	    ReadyPath: "/health/ready",
//	    StartPath: "/health/startup",
//	}))
//
// # Probe Semantics
//
// The three probes follow Kubernetes conventions:
//
//   - Liveness: indicates the process is running. A failing liveness
//     probe triggers a container restart.
//   - Readiness: indicates the service can accept traffic. A failing
//     readiness probe removes the pod from service endpoints.
//   - Startup: indicates initial startup has completed. Until the
//     startup probe succeeds, liveness and readiness probes are ignored.
//
// # Checker Timeout
//
// Each checker call is guarded by [Config].CheckerTimeout (default 5s).
// If a checker does not return within the timeout, the probe responds
// with 503 unavailable. This prevents a slow dependency (e.g., a
// database ping) from blocking the health endpoint indefinitely.
//
// Note: when a timeout fires, the middleware cancels the context and
// waits for the checker goroutine to return before recycling the
// [celeris.Context]. A checker that blocks forever and ignores context
// cancellation will therefore block the request goroutine indefinitely.
// Checkers should always select on ctx.Done() or otherwise respect the
// deadline to avoid this.
//
// # Skip Function
//
// Set [Config].Skip to bypass the middleware for certain requests before
// path matching occurs. This is useful for conditional healthcheck
// routing based on request properties.
//
// # Performance
//
// When [Config].CheckerTimeout is zero or negative (after applyDefaults,
// set it to [FastPathTimeout] to opt in), the checker runs synchronously
// inline with zero goroutine, channel, or context overhead. Use this
// fast-path for trivial checkers that cannot block:
//
//	healthcheck.New(healthcheck.Config{CheckerTimeout: healthcheck.FastPathTimeout})
//
// # Disabling Probes
//
// Setting a probe path to the empty string disables that probe entirely.
// Requests to the disabled path pass through to the next handler:
//
//	healthcheck.New(healthcheck.Config{
//	    LivePath:  "/livez",
//	    ReadyPath: "/readyz",
//	    StartPath: "", // startup probe disabled
//	})
//
// # Checker Panics
//
// If a checker panics, the probe returns 503 unavailable. The panic is
// recovered and does not crash the server.
//
// # Validation
//
// [Config].validate() panics at middleware construction time if paths are
// invalid (missing leading '/') or overlap. This is a programming error
// contract: validation failures are not recoverable at runtime.
//
// # Path Matching
//
// Probe paths are matched by exact string equality. There is no
// trailing-slash normalization: "/livez/" does NOT match "/livez".
// Configure paths without a trailing slash (the defaults already
// follow this convention).
//
// # Response Format
//
// 200: {"status": "ok"}
// 503: {"status": "unavailable"}
package healthcheck
