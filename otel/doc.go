// Package otel provides OpenTelemetry tracing and metrics middleware for celeris.
//
// The middleware creates a span for each HTTP request and records
// request duration and active request count as OTel metrics. Context
// propagation is handled automatically via the configured propagators,
// enabling distributed tracing across service boundaries.
//
// Basic usage with the global TracerProvider and MeterProvider:
//
//	server.Use(otel.New())
//
// # Explicit Providers
//
// For production deployments, configure explicit TracerProvider and
// MeterProvider instances instead of relying on globals:
//
//	tp := sdktrace.NewTracerProvider(
//	    sdktrace.WithBatcher(exporter),
//	    sdktrace.WithResource(res),
//	)
//	defer tp.Shutdown(ctx)
//
//	mp := sdkmetric.NewMeterProvider(
//	    sdkmetric.WithReader(reader),
//	    sdkmetric.WithResource(res),
//	)
//	defer mp.Shutdown(ctx)
//
//	server.Use(otel.New(otel.Config{
//	    TracerProvider: tp,
//	    MeterProvider:  mp,
//	}))
//
// # Downstream Span Access
//
// The middleware sets the span context on c.Context(), so downstream
// handlers can retrieve it for child spans or baggage. Use the
// convenience helper [SpanFromContext]:
//
//	span := otel.SpanFromContext(c)
//	span.AddEvent("processing started")
//
// # Span Naming
//
// By default, spans are named "METHOD /route/pattern" (e.g. "GET /users/:id").
// Override this with [Config].SpanNameFormatter.
//
// # Span Attributes
//
// Each span is annotated with the following attributes:
//
//   - http.request.method -- HTTP method (GET, POST, etc.)
//   - http.route -- registered route pattern (e.g. "/users/:id")
//   - url.scheme -- request scheme (http or https)
//   - url.path -- actual request path
//   - client.address -- client IP address (opt-in via [Config].CollectClientIP)
//   - server.address -- Host header value
//   - user_agent.original -- User-Agent header value (opt-out via [Config].CollectUserAgent)
//   - network.protocol.version -- protocol version (e.g. "1.1")
//   - http.response.status_code -- response status code (set after handler)
//   - http.response.body.size -- response body size in bytes (set after handler)
//
// Use [Config].CustomAttributes to append additional per-request span
// attributes:
//
//	server.Use(otel.New(otel.Config{
//	    CustomAttributes: func(c *celeris.Context) []attribute.KeyValue {
//	        return []attribute.KeyValue{
//	            attribute.String("tenant.id", c.Header("X-Tenant-ID")),
//	        }
//	    },
//	}))
//
// # PII Controls
//
// By default, the client IP address (client.address) is not recorded in
// span attributes because it is PII. Set [Config].CollectClientIP to true
// to opt in. The User-Agent header (user_agent.original) is recorded by
// default for backwards compatibility; set [Config].CollectUserAgent to
// false to suppress it.
//
// # Filtering
//
// Use [Config].Skip or [Config].SkipPaths to exclude health checks and
// other endpoints from tracing. [Config].Filter provides an allow-list
// alternative (kept for OTel ecosystem convention compatibility):
//
//	server.Use(otel.New(otel.Config{
//	    SkipPaths: []string{"/health", "/ready"},
//	}))
//
// # Metrics
//
// The middleware records four instruments:
//   - http.server.request.duration (Float64Histogram, seconds)
//   - http.server.active_requests (Int64UpDownCounter)
//   - http.server.request.body.size (Int64Histogram, bytes) -- recorded when > 0
//   - http.server.response.body.size (Int64Histogram, bytes) -- recorded when > 0
//
// All are tagged with http.request.method, http.route, url.scheme,
// server.address, and http.response.status_code.
//
// Use [Config].CustomMetricAttributes to append additional per-request
// metric attributes:
//
//	server.Use(otel.New(otel.Config{
//	    CustomMetricAttributes: func(c *celeris.Context) []attribute.KeyValue {
//	        return []attribute.KeyValue{
//	            attribute.String("cloud.region", "us-east-1"),
//	        }
//	    },
//	}))
//
// # Tracing-Only Mode
//
// Set [Config].DisableMetrics to true to skip all metric instrument creation
// and recording. Only tracing is active in this mode:
//
//	server.Use(otel.New(otel.Config{
//	    DisableMetrics: true,
//	}))
package otel
