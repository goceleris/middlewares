// Package debug provides a debug/introspection middleware for celeris.
//
// The middleware intercepts requests matching a configurable prefix
// (default "/debug/celeris") and serves JSON endpoints for server
// status, metrics, configuration, registered routes, memory statistics,
// and build information. Requests that do not match the prefix are
// passed through to the next handler with zero overhead beyond a
// string prefix check.
//
// Basic usage:
//
//	server.Use(debug.New(debug.Config{
//	    Server:    server,
//	    Collector: collector,
//	}))
//
// Endpoints:
//
//   - {prefix}/        -- index: returns a JSON array of available endpoint paths
//   - {prefix}/status  -- uptime and Go version
//   - {prefix}/metrics -- observe.Snapshot as JSON
//   - {prefix}/config  -- runtime info (OS, arch, CPUs, goroutines)
//   - {prefix}/routes  -- registered routes from Server.Routes()
//   - {prefix}/memory  -- heap, GC, and allocation statistics
//   - {prefix}/build   -- module path, Go version, and VCS info
//
// # Selective Endpoints
//
// [Config].Endpoints selectively enables or disables individual endpoints.
// Keys are endpoint names ("status", "metrics", "config", "routes", "memory",
// "build"). A true value enables the endpoint; false disables it (404).
// When nil (default), all endpoints are enabled. The index endpoint
// reflects only the enabled endpoints.
//
//	server.Use(debug.New(debug.Config{
//	    Server: server,
//	    Endpoints: map[string]bool{
//	        "status": true,
//	        "routes": true,
//	    },
//	}))
//
// # Security
//
// Debug endpoints expose sensitive operational details about your
// application, including memory statistics, build metadata, registered
// routes, and runtime configuration. This information can be valuable
// to attackers for fingerprinting and exploit development.
//
// By default, the middleware restricts access to loopback addresses
// (127.0.0.1 and ::1). In production deployments, always set AuthFunc
// to enforce authentication appropriate for your environment:
//
//	server.Use(debug.New(debug.Config{
//	    Server: server,
//	    AuthFunc: func(c *celeris.Context) bool {
//	        return c.Header("x-debug-token") == os.Getenv("DEBUG_TOKEN")
//	    },
//	}))
//
// To allow public access (not recommended in production):
//
//	AuthFunc: func(*celeris.Context) bool { return true }
//
// # MemStatsTTL
//
// [Config].MemStatsTTL controls how long the /memory endpoint caches
// runtime.ReadMemStats results. ReadMemStats stops the world, so caching
// prevents performance degradation under load. Default: 1s. Set to 0 to
// disable caching (not recommended in production).
//
// # Skipping
//
// Use [Config].Skip to dynamically bypass the debug middleware for
// certain requests. When Skip returns true, the request is passed
// directly to the next handler without prefix matching or auth checks.
//
// # Graceful Degradation
//
// Server and Collector are optional. When nil, the corresponding
// endpoints return safe fallback responses (empty route list, 501 Not
// Implemented for metrics).
package debug
