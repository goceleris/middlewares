// Package metrics provides Prometheus metrics middleware for celeris.
//
// The middleware serves dual purposes: it records per-request metrics
// (counters, histograms, gauges) and exposes them in Prometheus text
// exposition format at a configurable endpoint (default "/metrics").
//
// Basic usage:
//
//	server.Use(metrics.New())
//
// Requests to "/metrics" return Prometheus-formatted output. All other
// requests are instrumented with request count, duration, and active
// request tracking.
//
// Custom configuration:
//
//	server.Use(metrics.New(metrics.Config{
//	    Path:      "/prom",
//	    Namespace: "myapp",
//	    Subsystem: "http",
//	    SkipPaths: []string{"/health", "/ready"},
//	}))
//
// # Security Warning
//
// The metrics endpoint exposes internal server metrics including request
// rates, latency distributions, Go runtime statistics, and process info.
// In production, protect it from public access using one of:
//   - [Config].AuthFunc -- inline authentication gate (returns 403 when false)
//   - A separate listener (bind to localhost or an internal port)
//   - Authentication middleware (e.g., basicauth or keyauth) on the metrics route
//   - Network-level restriction (firewall, VPC, Kubernetes NetworkPolicy)
//
// Example using AuthFunc:
//
//	server.Use(metrics.New(metrics.Config{
//	    AuthFunc: func(c *celeris.Context) bool {
//	        return c.Header("Authorization") == "Bearer secret-token"
//	    },
//	}))
//
// # Registered Metrics
//
//   - {namespace}_{subsystem}_requests_total (CounterVec): Total HTTP requests, labeled by method, path, status.
//   - {namespace}_{subsystem}_request_duration_seconds (HistogramVec): Request latency, labeled by method, path, status.
//   - {namespace}_{subsystem}_active_requests (Gauge): Currently in-flight requests.
//
// The subsystem segment is omitted when [Config].Subsystem is empty (the default).
//
// # Cardinality Protection
//
// Unmatched routes (404 responses with no registered route pattern) use the
// sentinel path label "<unmatched>" instead of the raw request path. This
// prevents high-cardinality label explosion from bot scanners or typos
// generating unbounded unique path values.
//
// # Constant Labels
//
// Use [Config].ConstLabels to attach constant labels to every registered
// metric (e.g., service name or environment):
//
//	server.Use(metrics.New(metrics.Config{
//	    ConstLabels: map[string]string{
//	        "service": "api",
//	        "env":     "production",
//	    },
//	}))
//
// # Subsystem
//
// Use [Config].Subsystem to add a Prometheus subsystem prefix between the
// namespace and the metric name (e.g., "myapp_http_requests_total"):
//
//	server.Use(metrics.New(metrics.Config{
//	    Namespace: "myapp",
//	    Subsystem: "http",
//	}))
//
// # Histogram Buckets
//
// [DefaultBuckets] provides fine-grained histogram boundaries optimized for
// sub-millisecond latency resolution:
//
//	[]float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5}
//
// Override with [Config].Buckets for application-specific latency profiles:
//
//	server.Use(metrics.New(metrics.Config{
//	    Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10},
//	}))
//
// # Registry Isolation
//
// By default, the middleware creates a dedicated [prometheus.Registry] with
// Go runtime and process collectors. Pass a custom [Config].Registry to use
// a shared or pre-configured registry.
package metrics
