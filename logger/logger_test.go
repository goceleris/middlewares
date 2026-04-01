package logger

import (
	"bytes"
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
		Fields: func(c *celeris.Context, _ time.Duration) []slog.Attr {
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
	handler := func(c *celeris.Context) error {
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
	f.Fuzz(func(t *testing.T, status int) {
		_ = defaultLevel(status)
	})
}
