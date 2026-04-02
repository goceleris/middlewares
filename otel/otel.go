package otel

import (
	"time"

	"github.com/goceleris/celeris"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName             = "github.com/goceleris/middlewares/otel"
	instrumentationVersion = "0.2.0"
)

// SpanFromContext returns the active OpenTelemetry span from the request context.
// This is a convenience wrapper around trace.SpanFromContext(c.Context()).
func SpanFromContext(c *celeris.Context) trace.Span {
	return trace.SpanFromContext(c.Context())
}

// New creates an OpenTelemetry tracing and metrics middleware.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	tracer := cfg.TracerProvider.Tracer(tracerName,
		trace.WithInstrumentationVersion(instrumentationVersion),
	)

	metricsEnabled := !cfg.DisableMetrics
	var requestDuration metric.Float64Histogram
	var activeRequests metric.Int64UpDownCounter
	if metricsEnabled {
		meter := cfg.MeterProvider.Meter(tracerName,
			metric.WithInstrumentationVersion(instrumentationVersion),
		)
		requestDuration, _ = meter.Float64Histogram(
			"http.server.request.duration",
			metric.WithUnit("s"),
			metric.WithDescription("Duration of HTTP server requests"),
		)
		activeRequests, _ = meter.Int64UpDownCounter(
			"http.server.active_requests",
			metric.WithDescription("Number of active HTTP server requests"),
		)
	}

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	propagators := cfg.Propagators
	spanNameFmt := cfg.SpanNameFormatter
	serverSpanKind := trace.WithSpanKind(trace.SpanKindServer)
	customAttrs := cfg.CustomAttributes
	customMetricAttrs := cfg.CustomMetricAttributes
	collectClientIP := cfg.CollectClientIP
	collectUserAgent := cfg.CollectUserAgent == nil || *cfg.CollectUserAgent

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}
		if cfg.Filter != nil && !cfg.Filter(c) {
			return c.Next()
		}
		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		carrier := headerCarrier{ctx: c}
		parentCtx := propagators.Extract(c.Context(), carrier)

		spanName := c.Method()
		if fp := c.FullPath(); fp != "" {
			spanName += " " + fp
		}
		if spanNameFmt != nil {
			spanName = spanNameFmt(c)
		}

		var spanBuf [12]attribute.KeyValue
		n := 0
		spanBuf[n] = attribute.String("http.request.method", c.Method()); n++
		spanBuf[n] = attribute.String("http.route", c.FullPath()); n++
		spanBuf[n] = attribute.String("url.scheme", c.Scheme()); n++
		spanBuf[n] = attribute.String("url.path", c.Path()); n++
		spanBuf[n] = attribute.String("network.protocol.version", "1.1"); n++
		if collectClientIP {
			spanBuf[n] = attribute.String("client.address", c.ClientIP()); n++
		}
		spanBuf[n] = attribute.String("server.address", c.Host()); n++
		if collectUserAgent {
			spanBuf[n] = attribute.String("user_agent.original", c.Header("user-agent")); n++
		}
		spanAttrs := spanBuf[:n]
		if customAttrs != nil {
			spanAttrs = append(spanAttrs, customAttrs(c)...)
		}

		spanCtx, span := tracer.Start(parentCtx, spanName,
			serverSpanKind,
			trace.WithAttributes(spanAttrs...),
		)
		defer span.End()

		c.SetContext(spanCtx)
		propagators.Inject(spanCtx, carrier)

		if metricsEnabled {
			var metricBuf [6]attribute.KeyValue
			mn := 0
			metricBuf[mn] = attribute.String("http.request.method", c.Method()); mn++
			metricBuf[mn] = attribute.String("http.route", c.FullPath()); mn++
			metricBuf[mn] = attribute.String("url.scheme", c.Scheme()); mn++
			metricBuf[mn] = attribute.String("server.address", c.Host()); mn++
			metricBaseAttrs := metricBuf[:mn]
			if customMetricAttrs != nil {
				metricBaseAttrs = append(metricBaseAttrs, customMetricAttrs(c)...)
			}
			activeAttrSet := metric.WithAttributeSet(attribute.NewSet(metricBaseAttrs...))
			activeRequests.Add(spanCtx, 1, activeAttrSet)
			start := time.Now()

			err := c.Next()

			duration := time.Since(start).Seconds()
			status := c.StatusCode()

			if span.IsRecording() {
				span.SetAttributes(
					attribute.Int("http.response.status_code", status),
					attribute.Int64("http.response.body.size", int64(c.BytesWritten())),
				)
			}

			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			} else if status >= 500 {
				span.SetStatus(codes.Error, "")
			}

			allAttrs := append(metricBaseAttrs, attribute.Int("http.response.status_code", status))
			fullAttrSet := metric.WithAttributeSet(attribute.NewSet(allAttrs...))
			requestDuration.Record(spanCtx, duration, fullAttrSet)
			activeRequests.Add(spanCtx, -1, activeAttrSet)

			return err
		}

		err := c.Next()
		status := c.StatusCode()

		if span.IsRecording() {
			span.SetAttributes(
				attribute.Int("http.response.status_code", status),
				attribute.Int64("http.response.body.size", int64(c.BytesWritten())),
			)
		}

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else if status >= 500 {
			span.SetStatus(codes.Error, "")
		}

		return err
	}
}
