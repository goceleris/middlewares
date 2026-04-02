package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

func TestLoggerDefault(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	out := buf.String()
	if !strings.Contains(out, `"method":"GET"`) {
		t.Fatalf("missing method in log: %s", out)
	}
	if !strings.Contains(out, `"path":"/"`) {
		t.Fatalf("missing path in log: %s", out)
	}
	if !strings.Contains(out, `"status":200`) {
		t.Fatalf("missing status in log: %s", out)
	}
}

func TestLoggerSkipPaths(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log, SkipPaths: []string{"/health"}})
	_, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/health")
	testutil.AssertNoError(t, err)
	if buf.Len() > 0 {
		t.Fatalf("expected no log for skipped path, got: %s", buf.String())
	}
}

func TestLoggerSkipFunc(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{
		Output: log,
		Skip: func(c *celeris.Context) bool {
			return c.Path() == "/skip"
		},
	})
	_, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/skip")
	testutil.AssertNoError(t, err)
	if buf.Len() > 0 {
		t.Fatalf("expected no log for skipped request, got: %s", buf.String())
	}
}

func TestLoggerErrorLevel(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	handler := func(c *celeris.Context) error {
		return c.String(500, "error")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/fail")
	testutil.AssertNoError(t, err)
	if !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Fatalf("expected ERROR level for 500, got: %s", buf.String())
	}
}

func TestLoggerWarnLevel(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	handler := func(c *celeris.Context) error {
		return c.String(404, "not found")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/missing")
	testutil.AssertNoError(t, err)
	if !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Fatalf("expected WARN level for 404, got: %s", buf.String())
	}
}

func TestLoggerRequestID(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-request-id", "abc-123"))
	testutil.AssertNoError(t, err)
	if !strings.Contains(buf.String(), `"request_id":"abc-123"`) {
		t.Fatalf("missing request_id in log: %s", buf.String())
	}
}

func TestLoggerCustomFields(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{
		Output: log,
		Fields: func(_ *celeris.Context, _ time.Duration) []slog.Attr {
			return []slog.Attr{slog.String("custom", "value")}
		},
	})
	_, err := testutil.RunMiddleware(t, mw)
	testutil.AssertNoError(t, err)
	if !strings.Contains(buf.String(), `"custom":"value"`) {
		t.Fatalf("missing custom field in log: %s", buf.String())
	}
}

func TestLoggerClientIP(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	if !strings.Contains(buf.String(), `"client_ip":"1.2.3.4"`) {
		t.Fatalf("missing client_ip in log: %s", buf.String())
	}
}

func TestLoggerHandlerError(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	handler := func(_ *celeris.Context) error {
		return celeris.NewHTTPError(503, "service unavailable")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/err")
	testutil.AssertError(t, err)
	if !strings.Contains(buf.String(), `"error"`) {
		t.Fatalf("missing error field in log: %s", buf.String())
	}
}

func FuzzLoggerSkipPaths(f *testing.F) {
	f.Add("/health")
	f.Add("/metrics")
	f.Add("/")
	f.Add("")
	f.Fuzz(func(t *testing.T, path string) {
		log, buf := newTestLogger()
		mw := New(Config{Output: log, SkipPaths: []string{path}})
		ctx, _ := celeristest.NewContextT(t, "GET", path)
		_ = mw(ctx)
		if buf.Len() > 0 {
			t.Errorf("path %q should be skipped but was logged", path)
		}
	})
}

func FuzzLoggerStatus(f *testing.F) {
	f.Add(200)
	f.Add(404)
	f.Add(500)
	f.Add(0)
	f.Add(-1)
	f.Fuzz(func(_ *testing.T, status int) {
		_ = defaultLevel(status)
	})
}

func TestLoggerCaptureRequestBody(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Output: log, CaptureRequestBody: true})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "POST", "/body",
		celeristest.WithBody([]byte("hello world")))
	if !strings.Contains(buf.String(), "hello world") {
		t.Fatalf("expected request body in log: %s", buf.String())
	}
}

func TestLoggerCaptureResponseBody(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Output: log, CaptureResponseBody: true})
	handler := func(c *celeris.Context) error {
		return c.String(200, "response data")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/resp")
	if !strings.Contains(buf.String(), "response data") {
		t.Fatalf("expected response body in log: %s", buf.String())
	}
}

func TestLoggerMaxCaptureBytes(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Output: log, CaptureRequestBody: true, MaxCaptureBytes: 5})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "POST", "/trunc",
		celeristest.WithBody([]byte("hello world long body")))
	output := buf.String()
	if !strings.Contains(output, "hello") {
		t.Fatalf("expected truncated body in log: %s", output)
	}
	if strings.Contains(output, "hello world") {
		t.Fatalf("body should be truncated to 5 bytes: %s", output)
	}
}

func TestFastHandlerColorOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	log := slog.New(h)
	log.Info("test message")
	output := buf.String()
	if !strings.Contains(output, "\033[32m") {
		t.Fatalf("expected green color code for INFO, got: %q", output)
	}
	if !strings.Contains(output, "\033[0m") {
		t.Fatalf("expected color reset, got: %q", output)
	}
	if !strings.Contains(output, "INFO") {
		t.Fatalf("expected INFO in output, got: %q", output)
	}
}

func TestFastHandlerColorError(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	log := slog.New(h)
	log.Error("error message")
	output := buf.String()
	if !strings.Contains(output, "\033[31m") {
		t.Fatalf("expected red color code for ERROR, got: %q", output)
	}
}

func TestFastHandlerColorWarn(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	log := slog.New(h)
	log.Warn("warn message")
	output := buf.String()
	if !strings.Contains(output, "\033[33m") {
		t.Fatalf("expected yellow color code for WARN, got: %q", output)
	}
}

func TestFastHandlerColorDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Level: slog.LevelDebug, Color: true})
	log := slog.New(h)
	log.Debug("debug message")
	output := buf.String()
	if !strings.Contains(output, "\033[36m") {
		t.Fatalf("expected cyan color code for DEBUG, got: %q", output)
	}
}

func TestFastHandlerNoColorByDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, nil)
	log := slog.New(h)
	log.Info("test")
	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Fatalf("expected no color codes with default options, got: %q", output)
	}
}

func TestFastHandlerColorDisabled(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: false})
	log := slog.New(h)
	log.Info("test")
	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Fatalf("expected no color codes with Color=false, got: %q", output)
	}
}

func TestFastHandlerColorWithAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	log := slog.New(h).With("key", "value")
	log.Info("attrs test")
	output := buf.String()
	if !strings.Contains(output, "\033[32m") {
		t.Fatalf("expected color preserved through WithAttrs, got: %q", output)
	}
}

func TestFastHandlerColorWithGroup(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	log := slog.New(h).WithGroup("grp")
	log.Info("group test", "k", "v")
	output := buf.String()
	if !strings.Contains(output, "\033[32m") {
		t.Fatalf("expected color preserved through WithGroup, got: %q", output)
	}
}

func TestFastHandlerColorStatus(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	r.AddAttrs(slog.Int("status", 200))
	_ = h.Handle(context.Background(), r)
	output := buf.String()
	if !strings.Contains(output, "\033[32m") { // green for 2xx
		t.Fatalf("expected green for 200 status, got: %q", output)
	}
}

func TestFastHandlerColorStatus500(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	r := slog.NewRecord(time.Now(), slog.LevelError, "request", 0)
	r.AddAttrs(slog.Int("status", 503))
	_ = h.Handle(context.Background(), r)
	output := buf.String()
	if !strings.Contains(output, "\033[31m503") {
		t.Fatalf("expected red for 503 status, got: %q", output)
	}
}

func TestFastHandlerColorMethod(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	r.AddAttrs(slog.String("method", "GET"))
	_ = h.Handle(context.Background(), r)
	output := buf.String()
	if !strings.Contains(output, "\033[34m") { // blue for GET
		t.Fatalf("expected blue for GET method, got: %q", output)
	}
}

func TestFastHandlerColorLatency(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: true})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	r.AddAttrs(slog.Duration("latency", 500*time.Microsecond))
	_ = h.Handle(context.Background(), r)
	output := buf.String()
	if !strings.Contains(output, "\033[32m") { // green for <1ms
		t.Fatalf("expected green for sub-ms latency, got: %q", output)
	}
}

func TestAttrPoolResetOnHandlerError(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	handler := func(_ *celeris.Context) error {
		return celeris.NewHTTPError(503, "service unavailable")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Run three times to exercise the attrPool reuse path after an error.
	for i := range 3 {
		buf.Reset()
		_, err := testutil.RunChain(t, chain, "GET", "/err")
		testutil.AssertError(t, err)
		out := buf.String()
		if !strings.Contains(out, `"error"`) {
			t.Fatalf("iter %d: missing error field in log: %s", i, out)
		}
		// Verify no stale fields leak from a previous iteration by
		// ensuring the log entry does not contain duplicate method fields.
		count := strings.Count(out, `"method"`)
		if count != 1 {
			t.Fatalf("iter %d: expected 1 method field, got %d: %s", i, count, out)
		}
	}
}

func TestFastHandlerNoColorOnValues(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewFastHandler(buf, &FastHandlerOptions{Color: false})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	r.AddAttrs(slog.Int("status", 200), slog.String("method", "GET"))
	_ = h.Handle(context.Background(), r)
	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Fatalf("expected no color codes with Color=false, got: %q", output)
	}
}

func TestSensitiveHeadersRedacted(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{
		Output:           log,
		SensitiveHeaders: []string{"Authorization", "X-Api-Key"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/secret",
		celeristest.WithHeader("authorization", "Bearer token123"),
		celeristest.WithHeader("x-api-key", "secret-key"),
		celeristest.WithHeader("content-type", "application/json"),
	)
	testutil.AssertNoError(t, err)
	out := buf.String()
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in log for sensitive headers, got: %s", out)
	}
	if strings.Contains(out, "token123") {
		t.Fatalf("authorization value should be redacted, got: %s", out)
	}
	if strings.Contains(out, "secret-key") {
		t.Fatalf("x-api-key value should be redacted, got: %s", out)
	}
}

func TestSensitiveHeadersCaseInsensitive(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{
		Output:           log,
		SensitiveHeaders: []string{"AUTHORIZATION"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/case",
		celeristest.WithHeader("authorization", "Bearer xyz"),
	)
	testutil.AssertNoError(t, err)
	out := buf.String()
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected case-insensitive redaction, got: %s", out)
	}
}

func TestNoSensitiveHeadersNoRedaction(t *testing.T) {
	log, buf := newTestLogger()
	mw := New(Config{Output: log})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/no-redact",
		celeristest.WithHeader("authorization", "Bearer visible"),
	)
	testutil.AssertNoError(t, err)
	out := buf.String()
	if strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected no redaction without SensitiveHeaders, got: %s", out)
	}
}
