package metrics

import (
	"github.com/goceleris/celeris"
	"github.com/prometheus/client_golang/prometheus"
)

// DefaultBuckets provides fine-grained histogram buckets for sub-millisecond
// latency resolution, suitable for high-performance servers.
var DefaultBuckets = []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5}

// Config defines the metrics middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip from metrics recording (exact match).
	// The metrics endpoint itself is never recorded regardless of this list.
	SkipPaths []string

	// Path is the HTTP path that serves the Prometheus metrics endpoint.
	// Default: "/metrics".
	Path string

	// Namespace is the Prometheus metric namespace prefix.
	// Default: "celeris".
	Namespace string

	// Subsystem is the Prometheus metric subsystem prefix.
	// Default: "" (no subsystem).
	Subsystem string

	// Buckets defines the histogram bucket boundaries for request duration.
	// Default: DefaultBuckets.
	Buckets []float64

	// Registry is the Prometheus registry to use for metric registration and
	// gathering. When nil, the middleware creates a dedicated registry with
	// Go runtime and process collectors pre-registered.
	Registry *prometheus.Registry

	// ConstLabels are applied to every metric registration as constant labels
	// (e.g., service name, environment).
	ConstLabels map[string]string

	// AuthFunc is an authentication check executed before serving the metrics
	// endpoint. If it returns false, the middleware responds with 403 Forbidden.
	// Default: nil (no auth, all requests to the metrics endpoint are served).
	AuthFunc func(c *celeris.Context) bool

	// LabelFuncs defines custom label dimensions appended to all metric
	// label sets. Each map key becomes a label name and the function extracts
	// the label value from the request context. The functions are called
	// after c.Next() returns, so response-derived values are available.
	LabelFuncs map[string]func(*celeris.Context) string

	// HistogramOpts is an optional callback invoked during initialization for
	// each histogram metric. Use it to customize bucket boundaries or other
	// histogram options per-metric.
	HistogramOpts func(*prometheus.HistogramOpts)

	// CounterOpts is an optional callback invoked during initialization for
	// each counter metric. Use it to customize counter options per-metric.
	CounterOpts func(*prometheus.CounterOpts)
}

// DefaultConfig is the default metrics configuration.
var DefaultConfig = Config{}

func applyDefaults(cfg Config) Config {
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "celeris"
	}
	if len(cfg.Buckets) == 0 {
		cfg.Buckets = DefaultBuckets
	}
	return cfg
}

func (cfg Config) validate() {
	for i := 1; i < len(cfg.Buckets); i++ {
		if cfg.Buckets[i] <= cfg.Buckets[i-1] {
			panic("metrics: Buckets must be sorted in ascending order")
		}
	}
}
