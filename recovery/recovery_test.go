package recovery

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/goceleris/celeris"

	"github.com/goceleris/middlewares/internal/testutil"
)

func TestRecoveryFromPanic(t *testing.T) {
	mw := New()
	handler := func(_ *celeris.Context) error {
		panic("test panic")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/panic")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 500)
	testutil.AssertBodyContains(t, rec, "Internal Server Error")
}

func TestRecoveryFromErrorPanic(t *testing.T) {
	mw := New()
	handler := func(_ *celeris.Context) error {
		panic(errors.New("error panic"))
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/panic")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 500)
}

func TestRecoveryFromIntPanic(t *testing.T) {
	mw := New()
	handler := func(_ *celeris.Context) error {
		panic(42)
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/panic")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 500)
}

func TestRecoveryNoPanic(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/ok")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestRecoverySkip(t *testing.T) {
	mw := New(Config{
		Skip: func(_ *celeris.Context) bool { return true },
	})
	handler := func(_ *celeris.Context) error {
		panic("should not be caught")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate when skip=true")
		}
	}()
	_, _ = testutil.RunChain(t, chain, "GET", "/skip")
}

func TestRecoveryCustomHandler(t *testing.T) {
	mw := New(Config{
		ErrorHandler: func(c *celeris.Context, err any) error {
			return c.String(503, "custom: %v", err)
		},
	})
	handler := func(_ *celeris.Context) error {
		panic("boom")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/custom")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 503)
	testutil.AssertBodyContains(t, rec, "custom: boom")
}

func TestRecoveryLogsStack(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 4096, LogStack: true})
	handler := func(_ *celeris.Context) error {
		panic("stack test")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/stack")
	if !strings.Contains(buf.String(), "stack test") {
		t.Fatalf("expected panic value in log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "goroutine") {
		t.Fatalf("expected stack trace in log: %s", buf.String())
	}
}

func TestRecoveryNoStack(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, LogStack: false})
	handler := func(_ *celeris.Context) error {
		panic("no stack")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/nostack")
	if strings.Contains(buf.String(), "goroutine") {
		t.Fatalf("expected no stack trace: %s", buf.String())
	}
}

func TestRecoveryPassesError(t *testing.T) {
	mw := New()
	handler := func(_ *celeris.Context) error {
		return celeris.NewHTTPError(400, "bad request")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/error")
	testutil.AssertHTTPError(t, err, 400)
}

func TestErrAbortHandlerRepanics(t *testing.T) {
	mw := New(Config{LogStack: false})
	handler := func(_ *celeris.Context) error {
		panic(http.ErrAbortHandler)
	}
	chain := []celeris.HandlerFunc{mw, handler}
	defer func() {
		r := recover()
		if r != http.ErrAbortHandler {
			t.Fatalf("expected http.ErrAbortHandler re-panic, got %v", r)
		}
	}()
	_, _ = testutil.RunChain(t, chain, "GET", "/abort")
	t.Fatal("expected panic, not normal return")
}

func TestRecoveryLogsMethodAndPath(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 4096, LogStack: true})
	handler := func(_ *celeris.Context) error {
		panic("method path test")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "POST", "/test-path")
	output := buf.String()
	if !strings.Contains(output, `"method":"POST"`) {
		t.Fatalf("expected method in log: %s", output)
	}
	if !strings.Contains(output, `"path":"/test-path"`) {
		t.Fatalf("expected path in log: %s", output)
	}
}

func TestRecoveryLogsMethodAndPathNoStack(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, LogStack: true, StackSize: 0})
	handler := func(_ *celeris.Context) error {
		panic("no stack method path")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "DELETE", "/delete-path")
	output := buf.String()
	if !strings.Contains(output, `"method":"DELETE"`) {
		t.Fatalf("expected method in log: %s", output)
	}
	if !strings.Contains(output, `"path":"/delete-path"`) {
		t.Fatalf("expected path in log: %s", output)
	}
}

func TestStackAllCapturesAllGoroutines(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 8192, LogStack: true, StackAll: true})
	handler := func(_ *celeris.Context) error {
		panic("stack all test")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/stackall")
	output := buf.String()
	if !strings.Contains(output, "goroutine") {
		t.Fatalf("expected goroutine in stack: %s", output)
	}
}

func FuzzRecoveryPanicValues(f *testing.F) {
	f.Add("string panic")
	f.Add("")
	f.Fuzz(func(t *testing.T, val string) {
		mw := New(Config{LogStack: false})
		handler := func(_ *celeris.Context) error {
			panic(val)
		}
		chain := []celeris.HandlerFunc{mw, handler}
		rec, err := testutil.RunChain(t, chain, "GET", "/fuzz")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.StatusCode != 500 {
			t.Fatalf("expected 500, got %d", rec.StatusCode)
		}
	})
}
