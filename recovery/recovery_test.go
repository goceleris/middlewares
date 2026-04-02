package recovery

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"

	"github.com/goceleris/celeris"

	"github.com/goceleris/middlewares/internal/testutil"
)

// errBrokenPipe implements error and wraps syscall.EPIPE for testing.
type errBrokenPipe struct{}

func (e *errBrokenPipe) Error() string { return "broken pipe" }
func (e *errBrokenPipe) Is(target error) bool {
	return target == syscall.EPIPE
}

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
	mw := New(Config{Logger: log, StackSize: 65536, LogStack: true, StackAll: true})

	// Spin up a background goroutine that will show up in the stack dump.
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(ready)
		<-done
	}()
	<-ready

	handler := func(_ *celeris.Context) error {
		panic("stack all test")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/stackall")
	close(done)

	output := buf.String()
	// StackAll=true should capture multiple goroutine stacks.
	count := strings.Count(output, "goroutine")
	if count < 2 {
		t.Fatalf("expected multiple goroutine stacks with StackAll=true, found %d occurrences in: %s", count, output)
	}
}

func TestNestedRecoveryPanic(t *testing.T) {
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, _ any) error {
			panic("error handler panic")
		},
	})
	handler := func(_ *celeris.Context) error {
		panic("original panic")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/nested")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 500)
	// Verify the default 500 JSON body is returned when ErrorHandler panics.
	body := rec.BodyString()
	if !strings.Contains(body, "Internal Server Error") {
		t.Fatalf("expected default JSON error body, got: %s", body)
	}
	if !strings.Contains(body, "error") {
		t.Fatalf("expected JSON with 'error' key, got: %s", body)
	}
}

func TestBrokenPipeHandlerReceivesError(t *testing.T) {
	var receivedErr any
	mw := New(Config{
		LogStack: false,
		BrokenPipeHandler: func(c *celeris.Context, err any) error {
			receivedErr = err
			return c.NoContent(499)
		},
	})
	handler := func(_ *celeris.Context) error {
		panic(&net.OpError{Op: "write", Err: &errBrokenPipe{}})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/broken")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 499)
	if receivedErr == nil {
		t.Fatal("expected BrokenPipeHandler to receive the error")
	}
	// Verify the error is the correct type (*net.OpError wrapping EPIPE).
	opErr, ok := receivedErr.(*net.OpError)
	if !ok {
		t.Fatalf("expected *net.OpError, got %T", receivedErr)
	}
	if opErr.Op != "write" {
		t.Fatalf("expected Op=write, got %q", opErr.Op)
	}
	if !errors.Is(opErr.Err, syscall.EPIPE) {
		t.Fatalf("expected EPIPE wrapped error, got %v", opErr.Err)
	}
}

func TestDisableBrokenPipeLogSuppressesLog(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{
		Logger:               log,
		LogStack:             true,
		DisableBrokenPipeLog: true,
	})
	handler := func(_ *celeris.Context) error {
		panic(&net.OpError{Op: "write", Err: &errBrokenPipe{}})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/broken-no-log")
	if buf.Len() > 0 {
		t.Fatalf("expected no log with DisableBrokenPipeLog=true, got: %s", buf.String())
	}

	// Verify that normal (non-broken-pipe) panics are still logged even
	// when DisableBrokenPipeLog is true.
	buf.Reset()
	normalHandler := func(_ *celeris.Context) error {
		panic("normal panic")
	}
	normalChain := []celeris.HandlerFunc{mw, normalHandler}
	_, _ = testutil.RunChain(t, normalChain, "GET", "/normal-panic")
	if buf.Len() == 0 {
		t.Fatal("expected normal panics to still be logged when DisableBrokenPipeLog=true")
	}
	if !strings.Contains(buf.String(), "normal panic") {
		t.Fatalf("expected 'normal panic' in log, got: %s", buf.String())
	}
}

func TestBrokenPipeLogEnabledByDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{
		Logger:   log,
		LogStack: true,
	})
	handler := func(_ *celeris.Context) error {
		panic(&net.OpError{Op: "write", Err: &errBrokenPipe{}})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/broken-log")
	if !strings.Contains(buf.String(), "broken pipe") {
		t.Fatalf("expected broken pipe log by default, got: %s", buf.String())
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
