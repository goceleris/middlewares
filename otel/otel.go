package otel

import (
	"time"

	"github.com/goceleris/celeris"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.32.0"
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
	var requestBodySize metric.Int64Histogram
	var responseBodySize metric.Int64Histogram
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
		requestBodySize, _ = meter.Int64Histogram(
			"http.server.request.body.size",
			metric.WithUnit("By"),
			metric.WithDescription("Size of HTTP server request bodies"),
		)
		responseBodySize, _ = meter.Int64Histogram(
			"http.server.response.body.size",
			metric.WithUnit("By"),
			metric.WithDescription("Size of HTTP server response bodies"),
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
		spanBuf[n] = semconv.HTTPRequestMethodKey.String(c.Method())
		n++
		spanBuf[n] = semconv.HTTPRoute(c.FullPath())
		n++
		spanBuf[n] = semconv.URLScheme(c.Scheme())
		n++
		spanBuf[n] = semconv.URLPath(c.Path())
		n++
		// TODO: celeris Context does not expose the protocol version;
		// default to "1.1". Update when Context.Protocol() is available.
		spanBuf[n] = semconv.NetworkProtocolVersion("1.1")
		n++
		if collectClientIP {
			spanBuf[n] = semconv.ClientAddress(c.ClientIP())
			n++
		}
		spanBuf[n] = semconv.ServerAddress(c.Host())
		n++
		if collectUserAgent {
			spanBuf[n] = semconv.UserAgentOriginal(c.Header("user-agent"))
			n++
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
			metricBuf[mn] = semconv.HTTPRequestMethodKey.String(c.Method())
			mn++
			metricBuf[mn] = semconv.HTTPRoute(c.FullPath())
			mn++
			metricBuf[mn] = semconv.URLScheme(c.Scheme())
			mn++
			metricBuf[mn] = semconv.ServerAddress(c.Host())
			mn++
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
					semconv.HTTPResponseStatusCode(status),
					semconv.HTTPResponseBodySize(c.BytesWritten()),
				)
			}

			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			} else if status >= 500 {
				span.SetStatus(codes.Error, "")
			}

			allAttrs := append(metricBaseAttrs, semconv.HTTPResponseStatusCode(status))
			fullAttrSet := metric.WithAttributeSet(attribute.NewSet(allAttrs...))
			requestDuration.Record(spanCtx, duration, fullAttrSet)
			activeRequests.Add(spanCtx, -1, activeAttrSet)

			if reqSize := c.ContentLength(); reqSize > 0 {
				requestBodySize.Record(spanCtx, reqSize, fullAttrSet)
			}
			if respSize := int64(c.BytesWritten()); respSize > 0 {
				responseBodySize.Record(spanCtx, respSize, fullAttrSet)
			}

			return err
		}

		err := c.Next()
		status := c.StatusCode()

		if span.IsRecording() {
			span.SetAttributes(
				semconv.HTTPResponseStatusCode(status),
				semconv.HTTPResponseBodySize(c.BytesWritten()),
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
