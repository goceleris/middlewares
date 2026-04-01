package timeout

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/middlewares/internal/testutil"
)

func TestNormalRequestCompletes(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestTimeoutExceeded(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Millisecond})
	handler := func(c *celeris.Context) error {
		time.Sleep(50 * time.Millisecond)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/slow")
	testutil.AssertHTTPError(t, err, 503)
}

func TestSkipBypassesTimeout(t *testing.T) {
	mw := New(Config{
		Timeout: 1 * time.Millisecond,
		Skip:    func(c *celeris.Context) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "skipped")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/skip")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "skipped")
}

func TestCustomErrorHandler(t *testing.T) {
	mw := New(Config{
		Timeout: 1 * time.Millisecond,
		ErrorHandler: func(c *celeris.Context) error {
			return celeris.NewHTTPError(504, "Gateway Timeout")
		},
	})
	handler := func(c *celeris.Context) error {
		time.Sleep(50 * time.Millisecond)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/custom")
	testutil.AssertHTTPError(t, err, 504)
}

func TestCustomTimeoutDuration(t *testing.T) {
	mw := New(Config{Timeout: 500 * time.Millisecond})
	handler := func(c *celeris.Context) error {
		return c.String(200, "fast")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/fast")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestDefaultConfigValues(t *testing.T) {
	if DefaultConfig.Timeout != 5*time.Second {
		t.Fatalf("default timeout: got %v, want 5s", DefaultConfig.Timeout)
	}
}

func TestApplyDefaultsFixesZeroTimeout(t *testing.T) {
	cfg := applyDefaults(Config{Timeout: 0})
	if cfg.Timeout != 5*time.Second {
		t.Fatalf("expected 5s, got %v", cfg.Timeout)
	}
}

func TestApplyDefaultsFixesNegativeTimeout(t *testing.T) {
	cfg := applyDefaults(Config{Timeout: -1 * time.Second})
	if cfg.Timeout != 5*time.Second {
		t.Fatalf("expected 5s, got %v", cfg.Timeout)
	}
}

func TestDeadlinePropagated(t *testing.T) {
	mw := New(Config{Timeout: 2 * time.Second})
	var hasDeadline bool
	handler := func(c *celeris.Context) error {
		_, hasDeadline = c.Context().Deadline()
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/deadline")
	testutil.AssertNoError(t, err)
	if !hasDeadline {
		t.Fatal("expected context to have a deadline")
	}
}

func TestContextCancelCalled(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second})
	var childCtx context.Context
	handler := func(c *celeris.Context) error {
		childCtx = c.Context()
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/cancel")
	testutil.AssertNoError(t, err)

	// After middleware returns, defer cancel() should have fired.
	select {
	case <-childCtx.Done():
		// context was cancelled
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected context to be cancelled after middleware returns")
	}
}

func TestHandlerErrorPassesThroughWithoutTimeout(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second})
	handler := func(c *celeris.Context) error {
		return celeris.NewHTTPError(400, "bad request")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/error")
	testutil.AssertHTTPError(t, err, 400)
}

func TestHandlerBareErrorPassesThrough(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second})
	handler := func(c *celeris.Context) error {
		return errors.New("something went wrong")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/bare-error")
	testutil.AssertError(t, err)
}

func TestDefaultConfigNoArgs(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "default")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/default")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func FuzzTimeoutDurations(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(-1))
	f.Add(int64(1))
	f.Add(int64(5000000000)) // 5s
	f.Add(int64(9223372036854775807))
	f.Fuzz(func(t *testing.T, ns int64) {
		mw := New(Config{Timeout: time.Duration(ns)})
		handler := func(c *celeris.Context) error {
			return c.String(200, "ok")
		}
		chain := []celeris.HandlerFunc{mw, handler}
		testutil.RunChain(t, chain, "GET", "/fuzz")
	})
}
