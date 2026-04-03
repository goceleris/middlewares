package recovery

import (
	"bytes"
	"context"
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
	// Zero-value DisableLogStack = false means stacks are logged by default.
	mw := New(Config{Logger: log, StackSize: 4096})
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
	mw := New(Config{Logger: log, DisableLogStack: true})
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
	mw := New(Config{DisableLogStack: true})
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
	mw := New(Config{Logger: log, StackSize: 4096})
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
	// StackSize=0 disables stack capture (fix #1 allows 0).
	// Panic value, method, and path are still logged.
	mw := New(Config{Logger: log, StackSize: 0})
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
	if strings.Contains(output, "goroutine") {
		t.Fatalf("expected no stack trace with StackSize=0, got: %s", output)
	}
}

func TestStackAllCapturesAllGoroutines(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 65536, StackAll: true})

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
		DisableLogStack: true,
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

func TestBrokenPipeNilHandlerReturnsSentinel(t *testing.T) {
	mw := New(Config{DisableLogStack: true})
	handler := func(_ *celeris.Context) error {
		panic(&net.OpError{Op: "write", Err: &errBrokenPipe{}})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/broken-sentinel")
	if !errors.Is(err, ErrBrokenPipe) {
		t.Fatalf("expected ErrBrokenPipe sentinel, got %v", err)
	}
}

func TestBrokenPipeDirectEPIPE(t *testing.T) {
	// errBrokenPipe implements Is(syscall.EPIPE) directly, no net.OpError wrapper.
	mw := New(Config{DisableLogStack: true})
	handler := func(_ *celeris.Context) error {
		panic(&errBrokenPipe{})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/broken-direct")
	if !errors.Is(err, ErrBrokenPipe) {
		t.Fatalf("expected ErrBrokenPipe sentinel, got %v", err)
	}
}

func TestValidateRejectsNegativeStackSize(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for negative StackSize")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "StackSize") {
			t.Fatalf("expected StackSize panic message, got: %v", r)
		}
	}()
	New(Config{StackSize: -1})
}

func TestNestedRecoveryLogs(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{
		Logger: log,
		ErrorHandler: func(_ *celeris.Context, _ any) error {
			panic("handler exploded")
		},
	})
	handler := func(_ *celeris.Context) error {
		panic("original")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/nested-log")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 500)
	output := buf.String()
	if !strings.Contains(output, "handler exploded") {
		t.Fatalf("expected nested panic value in log, got: %s", output)
	}
	if !strings.Contains(output, "panic in error handler") {
		t.Fatalf("expected 'panic in error handler' message, got: %s", output)
	}
}

func TestDisableBrokenPipeLogSuppressesLog(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{
		Logger:               log,
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
	mw := New(Config{Logger: log})
	handler := func(_ *celeris.Context) error {
		panic(&net.OpError{Op: "write", Err: &errBrokenPipe{}})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/broken-log")
	if !strings.Contains(buf.String(), "broken pipe") {
		t.Fatalf("expected broken pipe log by default, got: %s", buf.String())
	}
}

// --- DisableLogStack tests ---

func TestDisableLogStackZeroValueLogsStack(t *testing.T) {
	// The whole point of the rename: zero-value DisableLogStack should log stacks.
	// StackSize must be set explicitly since 0 now means "no stack capture".
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 4096})
	handler := func(_ *celeris.Context) error { panic("zero-value test") }
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/zero-value")
	if !strings.Contains(buf.String(), "goroutine") {
		t.Fatalf("expected stack trace with zero-value DisableLogStack, got: %s", buf.String())
	}
}

func TestDisableLogStackTrueSuppressesLog(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, DisableLogStack: true})
	handler := func(_ *celeris.Context) error { panic("suppress test") }
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/suppress")
	if buf.Len() > 0 {
		t.Fatalf("expected no log with DisableLogStack=true, got: %s", buf.String())
	}
}

func TestDeprecatedLogStackOverridesDisableLogStack(t *testing.T) {
	// LogStack: true should force DisableLogStack to false even if both are set.
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 4096, DisableLogStack: true, LogStack: true})
	handler := func(_ *celeris.Context) error { panic("compat test") }
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/compat")
	if !strings.Contains(buf.String(), "goroutine") {
		t.Fatalf("expected stack trace when LogStack=true overrides DisableLogStack, got: %s", buf.String())
	}
}

// errConnAborted implements error and wraps syscall.ECONNABORTED for testing.
type errConnAborted struct{}

func (e *errConnAborted) Error() string { return "connection aborted" }
func (e *errConnAborted) Is(target error) bool {
	return target == syscall.ECONNABORTED
}

func TestBrokenPipeECONNABORTED(t *testing.T) {
	mw := New(Config{DisableLogStack: true})
	handler := func(_ *celeris.Context) error {
		panic(&errConnAborted{})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/broken-connaborted")
	if !errors.Is(err, ErrBrokenPipe) {
		t.Fatalf("expected ErrBrokenPipe sentinel for ECONNABORTED, got %v", err)
	}
}

func TestBrokenPipeECONNABORTEDOpError(t *testing.T) {
	mw := New(Config{DisableLogStack: true})
	handler := func(_ *celeris.Context) error {
		panic(&net.OpError{Op: "write", Err: &errConnAborted{}})
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/broken-connaborted-op")
	if !errors.Is(err, ErrBrokenPipe) {
		t.Fatalf("expected ErrBrokenPipe sentinel for ECONNABORTED via OpError, got %v", err)
	}
}

func TestPanicAfterResponseWritten(t *testing.T) {
	mw := New(Config{DisableLogStack: true})
	handler := func(c *celeris.Context) error {
		_ = c.String(200, "ok")
		panic("late panic")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/written-then-panic")
	// The middleware should NOT overwrite the already-committed 200 response.
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
	// The error should propagate instead of writing a second response.
	testutil.AssertError(t, err)
	if !strings.Contains(err.Error(), "response committed") {
		t.Fatalf("expected 'response committed' in error, got: %v", err)
	}
}

func TestPanicAfterContextCancelled(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log})
	handler := func(c *celeris.Context) error {
		// Cancel the context before panicking.
		ctx, cancel := context.WithCancel(c.Context())
		cancel()
		c.SetContext(ctx)
		panic("cancelled panic")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/cancelled-panic")
	// The middleware should return an error without writing a response.
	testutil.AssertError(t, err)
	if !strings.Contains(err.Error(), "recovery: panic:") {
		t.Fatalf("expected 'recovery: panic:' in error, got: %v", err)
	}
	// Verify the WARN-level "context cancelled" log was emitted.
	output := buf.String()
	if !strings.Contains(output, "panic after context cancelled") {
		t.Fatalf("expected 'panic after context cancelled' in log, got: %s", output)
	}
}

func TestLogLevelConfig(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mw := New(Config{Logger: log, StackSize: 4096, LogLevel: slog.LevelWarn})
	handler := func(_ *celeris.Context) error {
		panic("level test")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/log-level")
	output := buf.String()
	if !strings.Contains(output, `"level":"WARN"`) {
		t.Fatalf("expected WARN level in log, got: %s", output)
	}
}

func TestLogLevelDefaultIsError(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))
	mw := New(Config{Logger: log, StackSize: 4096})
	handler := func(_ *celeris.Context) error {
		panic("default level")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/log-level-default")
	output := buf.String()
	if !strings.Contains(output, `"level":"ERROR"`) {
		t.Fatalf("expected ERROR level in log (default), got: %s", output)
	}
}

func FuzzRecoveryPanicValues(f *testing.F) {
	f.Add("string panic")
	f.Add("")
	f.Fuzz(func(t *testing.T, val string) {
		mw := New(Config{DisableLogStack: true})
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
