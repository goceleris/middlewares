package otel

import (
	"context"
	"errors"
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func newTestTP() (*sdktrace.TracerProvider, *tracetest.InMemoryExporter) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	return tp, exp
}

func runChain(t *testing.T, chain []celeris.HandlerFunc, method, path string, opts ...celeristest.Option) error {
	t.Helper()
	allOpts := make([]celeristest.Option, 0, len(opts)+1)
	allOpts = append(allOpts, celeristest.WithHandlers(chain...))
	allOpts = append(allOpts, opts...)
	ctx, _ := celeristest.NewContextT(t, method, path, allOpts...)
	return ctx.Next()
}

func TestSpanCreated(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]
	if span.SpanKind != trace.SpanKindServer {
		t.Fatalf("expected SpanKindServer, got %v", span.SpanKind)
	}
}

func TestSpanName(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "POST", "/api/items")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	// FullPath is empty in test context (no router), so name is just "POST".
	if got := spans[0].Name; got != "POST" {
		t.Fatalf("expected span name %q, got %q", "POST", got)
	}
}

func TestSpanNameFormatter(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		SpanNameFormatter: func(c *celeris.Context) string {
			return "custom " + c.Path()
		},
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/custom-path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if got := spans[0].Name; got != "custom /custom-path" {
		t.Fatalf("expected span name %q, got %q", "custom /custom-path", got)
	}
}

func TestSpanAttributes(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp, CollectClientIP: true})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/attrs",
		celeristest.WithHeader("x-forwarded-for", "10.0.0.1"),
		celeristest.WithHeader("user-agent", "TestAgent/1.0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}

	if got := attrMap["http.request.method"].AsString(); got != "GET" {
		t.Fatalf("expected http.request.method=GET, got %q", got)
	}
	if got := attrMap["url.scheme"].AsString(); got != "http" {
		t.Fatalf("expected url.scheme=http, got %q", got)
	}
	if got := attrMap["client.address"].AsString(); got != "10.0.0.1" {
		t.Fatalf("expected client.address=10.0.0.1, got %q", got)
	}
	if got := attrMap["http.response.status_code"].AsInt64(); got != 200 {
		t.Fatalf("expected http.response.status_code=200, got %d", got)
	}
	if got := attrMap["user_agent.original"].AsString(); got != "TestAgent/1.0" {
		t.Fatalf("expected user_agent.original=TestAgent/1.0, got %q", got)
	}
	if got := attrMap["url.path"].AsString(); got != "/attrs" {
		t.Fatalf("expected url.path=/attrs, got %q", got)
	}
	if got := attrMap["network.protocol.version"].AsString(); got != "1.1" {
		t.Fatalf("expected network.protocol.version=1.1, got %q", got)
	}
	if got := attrMap["http.response.body.size"].AsInt64(); got != 2 {
		t.Fatalf("expected http.response.body.size=2, got %d", got)
	}
}

func TestSpanStatusError(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(503, "unavailable") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/fail")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Fatalf("expected span status Error for 503, got %v", spans[0].Status.Code)
	}
}

func TestSpanStatusUnset(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Unset {
		t.Fatalf("expected span status Unset for 200, got %v", spans[0].Status.Code)
	}
}

func TestHandlerError(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	want := errors.New("handler failed")
	handler := func(_ *celeris.Context) error { return want }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/err")
	if !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
}

func TestHandlerErrorRecordedOnSpan(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	want := errors.New("handler failed")
	handler := func(_ *celeris.Context) error { return want }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/err")
	if !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Fatalf("expected span status Error for handler error, got %v", spans[0].Status.Code)
	}
	if spans[0].Status.Description != "handler failed" {
		t.Fatalf("expected status description %q, got %q", "handler failed", spans[0].Status.Description)
	}
	// Verify error event was recorded.
	found := false
	for _, ev := range spans[0].Events {
		if ev.Name == "exception" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected exception event from RecordError, not found")
	}
}

func TestSkipFunc(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		Skip: func(c *celeris.Context) bool {
			return c.Path() == "/health"
		},
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/health")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 0 {
		t.Fatalf("expected 0 spans for skipped request, got %d", len(spans))
	}
}

func TestSkipPaths(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		SkipPaths:      []string{"/health", "/ready"},
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }

	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/health")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err = runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ready")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 0 {
		t.Fatalf("expected 0 spans for skipped paths, got %d", len(spans))
	}
}

func TestFilterAllowList(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		Filter: func(c *celeris.Context) bool {
			return c.Path() == "/traced"
		},
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }

	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/not-traced")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exp.GetSpans()) != 0 {
		t.Fatalf("expected 0 spans for filtered path, got %d", len(exp.GetSpans()))
	}

	err = runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/traced")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exp.GetSpans()) != 1 {
		t.Fatalf("expected 1 span for allowed path, got %d", len(exp.GetSpans()))
	}
}

func TestContextPropagation(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	prop := propagation.TraceContext{}

	mw := New(Config{
		TracerProvider: tp,
		Propagators:    prop,
	})

	// Create a parent span and inject its context into headers.
	parentTracer := tp.Tracer("test-parent")
	parentCtx, parentSpan := parentTracer.Start(context.Background(), "parent-op")
	defer parentSpan.End()

	carrier := propagation.MapCarrier{}
	prop.Inject(parentCtx, carrier)
	traceparent := carrier.Get("traceparent")
	if traceparent == "" {
		t.Fatal("expected traceparent header from parent span")
	}

	handler := func(c *celeris.Context) error {
		span := trace.SpanFromContext(c.Context())
		if !span.SpanContext().IsValid() {
			t.Error("expected valid span in context")
		}
		sc := span.SpanContext()
		parentSC := parentSpan.SpanContext()
		if sc.TraceID() != parentSC.TraceID() {
			t.Errorf("trace ID mismatch: got %s, want %s", sc.TraceID(), parentSC.TraceID())
		}
		return c.String(200, "ok")
	}

	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/propagated",
		celeristest.WithHeader("traceparent", traceparent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) < 1 {
		t.Fatal("expected at least 1 span")
	}
}

func TestContextSet(t *testing.T) {
	tp, _ := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	var capturedCtx context.Context
	handler := func(c *celeris.Context) error {
		capturedCtx = c.Context()
		return c.String(200, "ok")
	}
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ctx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	span := trace.SpanFromContext(capturedCtx)
	if !span.SpanContext().IsValid() {
		t.Fatal("expected middleware to set a valid span context on c.Context()")
	}
}

func TestNoopProviders(t *testing.T) {
	tp := tracenoop.NewTracerProvider()
	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/noop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	// Ensure New() with no args does not panic.
	mw := New()
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDisableMetrics(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		DisableMetrics: true,
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/metrics-off")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span even with DisableMetrics, got %d", len(spans))
	}
	if spans[0].Status.Code == codes.Error {
		t.Fatal("expected non-error span status")
	}
}

func TestDisableMetricsWithError(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		DisableMetrics: true,
	})
	want := errors.New("fail")
	handler := func(_ *celeris.Context) error { return want }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/err")
	if !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Fatalf("expected Error status with DisableMetrics, got %v", spans[0].Status.Code)
	}
}

func TestDisableMetrics500(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		DisableMetrics: true,
	})
	handler := func(c *celeris.Context) error { return c.String(500, "fail") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/500")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Fatalf("expected Error status for 500 with DisableMetrics, got %v", spans[0].Status.Code)
	}
}

func TestCustomAttributes(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		CustomAttributes: func(c *celeris.Context) []attribute.KeyValue {
			return []attribute.KeyValue{
				attribute.String("custom.key", "custom-value"),
				attribute.Int("custom.int", 42),
			}
		},
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/custom-attrs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["custom.key"].AsString(); got != "custom-value" {
		t.Fatalf("expected custom.key=custom-value, got %q", got)
	}
	if got := attrMap["custom.int"].AsInt64(); got != 42 {
		t.Fatalf("expected custom.int=42, got %d", got)
	}
	// Ensure standard attributes still present.
	if got := attrMap["http.request.method"].AsString(); got != "GET" {
		t.Fatalf("expected http.request.method=GET, got %q", got)
	}
}

func TestCustomMetricAttributes(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{
		TracerProvider: tp,
		CustomMetricAttributes: func(_ *celeris.Context) []attribute.KeyValue {
			return []attribute.KeyValue{
				attribute.String("region", "us-east-1"),
			}
		},
	})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/metric-attrs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
}

func TestResponseBodySizeAttribute(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "hello world") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/body-size")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["http.response.body.size"].AsInt64(); got != 11 {
		t.Fatalf("expected http.response.body.size=11, got %d", got)
	}
}

func TestUrlPathAttribute(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/api/users/123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["url.path"].AsString(); got != "/api/users/123" {
		t.Fatalf("expected url.path=/api/users/123, got %q", got)
	}
}

func TestNetworkProtocolVersion(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/proto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["network.protocol.version"].AsString(); got != "1.1" {
		t.Fatalf("expected network.protocol.version=1.1, got %q", got)
	}
}

func TestMetricSchemeAndServerAddress(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/scheme-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify span was created (metric attributes are internal, tested via no-panic).
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
}

// --- CollectClientIP tests ---

func TestCollectClientIPDefault(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// Default: CollectClientIP=false, client.address should be absent.
	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ip-test",
		celeristest.WithHeader("x-forwarded-for", "10.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "client.address" {
			t.Fatal("client.address should be absent when CollectClientIP is false (default)")
		}
	}
}

func TestCollectClientIPTrue(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp, CollectClientIP: true})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ip-test",
		celeristest.WithHeader("x-forwarded-for", "10.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["client.address"].AsString(); got != "10.0.0.1" {
		t.Fatalf("expected client.address=10.0.0.1, got %q", got)
	}
}

// --- CollectUserAgent tests ---

func TestCollectUserAgentDefault(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// Default: CollectUserAgent=nil (true), user_agent.original should be present.
	mw := New(Config{TracerProvider: tp})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ua-test",
		celeristest.WithHeader("user-agent", "TestBot/1.0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["user_agent.original"].AsString(); got != "TestBot/1.0" {
		t.Fatalf("expected user_agent.original=TestBot/1.0, got %q", got)
	}
}

func TestCollectUserAgentFalse(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	f := false
	mw := New(Config{TracerProvider: tp, CollectUserAgent: &f})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ua-test",
		celeristest.WithHeader("user-agent", "TestBot/1.0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "user_agent.original" {
			t.Fatal("user_agent.original should be absent when CollectUserAgent is false")
		}
	}
}

func TestSpanFromContext(t *testing.T) {
	tp, _ := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	mw := New(Config{TracerProvider: tp})
	var span trace.Span
	handler := func(c *celeris.Context) error {
		span = SpanFromContext(c)
		return c.String(200, "ok")
	}
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/span-helper")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if span == nil {
		t.Fatal("SpanFromContext returned nil")
	}
	if !span.SpanContext().IsValid() {
		t.Fatal("SpanFromContext returned invalid span")
	}
}

func TestSpanFromContextWithoutMiddleware(t *testing.T) {
	handler := func(c *celeris.Context) error {
		span := SpanFromContext(c)
		if span == nil {
			t.Fatal("SpanFromContext should never return nil (returns noop span)")
		}
		return c.String(200, "ok")
	}
	err := runChain(t, []celeris.HandlerFunc{handler}, "GET", "/no-otel")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCollectUserAgentExplicitTrue(t *testing.T) {
	tp, exp := newTestTP()
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tr := true
	mw := New(Config{TracerProvider: tp, CollectUserAgent: &tr})
	handler := func(c *celeris.Context) error { return c.String(200, "ok") }
	err := runChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/ua-test",
		celeristest.WithHeader("user-agent", "TestBot/1.0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	attrMap := make(map[string]attribute.Value, len(spans[0].Attributes))
	for _, a := range spans[0].Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	if got := attrMap["user_agent.original"].AsString(); got != "TestBot/1.0" {
		t.Fatalf("expected user_agent.original=TestBot/1.0, got %q", got)
	}
}
