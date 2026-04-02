package metrics

import (
	"bytes"
	"strconv"
	"time"

	"github.com/goceleris/celeris"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// New creates a Prometheus metrics middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	reg := cfg.Registry
	if reg == nil {
		reg = prometheus.NewRegistry()
		reg.MustRegister(prometheus.NewGoCollector())
		reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	}

	constLabels := prometheus.Labels(cfg.ConstLabels)

	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   cfg.Namespace,
		Subsystem:   cfg.Subsystem,
		Name:        "requests_total",
		Help:        "Total number of HTTP requests.",
		ConstLabels: constLabels,
	}, []string{"method", "path", "status"})

	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   cfg.Namespace,
		Subsystem:   cfg.Subsystem,
		Name:        "request_duration_seconds",
		Help:        "HTTP request duration in seconds.",
		Buckets:     cfg.Buckets,
		ConstLabels: constLabels,
	}, []string{"method", "path", "status"})

	activeRequests := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   cfg.Namespace,
		Subsystem:   cfg.Subsystem,
		Name:        "active_requests",
		Help:        "Number of currently active HTTP requests.",
		ConstLabels: constLabels,
	})

	reg.MustRegister(requestsTotal, requestDuration, activeRequests)

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	// Pre-cache status code strings for common codes.
	statusStrings := make(map[int]string, 17)
	for _, code := range []int{
		200, 201, 204,
		301, 302, 304,
		400, 401, 403, 404, 405, 408, 429,
		500, 502, 503, 504,
	} {
		statusStrings[code] = strconv.Itoa(code)
	}

	metricsPath := cfg.Path
	authFunc := cfg.AuthFunc

	return func(c *celeris.Context) error {
		if c.Path() == metricsPath {
			method := c.Method()
			if method != "GET" && method != "HEAD" {
				return c.Next()
			}
			if authFunc != nil && !authFunc(c) {
				c.Abort()
				return c.NoContent(403)
			}
			c.Abort()
			return serveMetrics(c, reg)
		}

		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}
		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		activeRequests.Inc()
		start := time.Now()

		err := c.Next()

		duration := time.Since(start).Seconds()
		activeRequests.Dec()

		status := c.StatusCode()
		statusStr, ok := statusStrings[status]
		if !ok {
			statusStr = strconv.Itoa(status)
		}

		path := c.FullPath()
		if path == "" {
			if status == 404 {
				path = "<unmatched>"
			} else {
				path = c.Path()
			}
		}

		requestsTotal.WithLabelValues(c.Method(), path, statusStr).Inc()
		requestDuration.WithLabelValues(c.Method(), path, statusStr).Observe(duration)

		return err
	}
}

func serveMetrics(c *celeris.Context, gatherer prometheus.Gatherer) error {
	mfs, err := gatherer.Gather()
	if err != nil {
		return c.String(500, "internal error")
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return c.String(500, "internal error")
		}
	}
	return c.Blob(200, "text/plain; version=0.0.4; charset=utf-8", buf.Bytes())
}
