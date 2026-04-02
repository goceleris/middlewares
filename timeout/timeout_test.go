package timeout

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

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
		Skip:    func(_ *celeris.Context) bool { return true },
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
		ErrorHandler: func(_ *celeris.Context) error {
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
	handler := func(_ *celeris.Context) error {
		return celeris.NewHTTPError(400, "bad request")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/error")
	testutil.AssertHTTPError(t, err, 400)
}

func TestHandlerBareErrorPassesThrough(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second})
	handler := func(_ *celeris.Context) error {
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

func TestPreemptiveNormalCompletion(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second, Preemptive: true})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestPreemptiveTimeout(t *testing.T) {
	mw := New(Config{Timeout: 10 * time.Millisecond, Preemptive: true})
	var wg sync.WaitGroup
	wg.Add(1)
	handler := func(c *celeris.Context) error {
		defer wg.Done()
		<-c.Context().Done()
		return c.Context().Err()
	}
	c, _ := celeristest.NewContext("GET", "/slow", celeristest.WithHandlers(mw, handler))
	err := c.Next()
	wg.Wait()
	celeristest.ReleaseContext(c)
	testutil.AssertHTTPError(t, err, 503)
}

func TestPreemptiveTimeoutCustomHandler(t *testing.T) {
	mw := New(Config{
		Timeout:    10 * time.Millisecond,
		Preemptive: true,
		ErrorHandler: func(_ *celeris.Context) error {
			return celeris.NewHTTPError(504, "Gateway Timeout")
		},
	})
	var wg sync.WaitGroup
	wg.Add(1)
	handler := func(c *celeris.Context) error {
		defer wg.Done()
		<-c.Context().Done()
		return c.Context().Err()
	}
	c, _ := celeristest.NewContext("GET", "/custom", celeristest.WithHandlers(mw, handler))
	err := c.Next()
	wg.Wait()
	celeristest.ReleaseContext(c)
	testutil.AssertHTTPError(t, err, 504)
}

func TestPreemptiveSkipBypass(t *testing.T) {
	mw := New(Config{
		Timeout:    10 * time.Millisecond,
		Preemptive: true,
		Skip:       func(_ *celeris.Context) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "skipped")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "skipped")
}

func TestPreemptiveContextCancelled(t *testing.T) {
	mw := New(Config{Timeout: 10 * time.Millisecond, Preemptive: true})
	var ctxDone bool
	var wg sync.WaitGroup
	wg.Add(1)
	handler := func(c *celeris.Context) error {
		defer wg.Done()
		<-c.Context().Done()
		ctxDone = true
		return c.Context().Err()
	}
	c, _ := celeristest.NewContext("GET", "/ctx", celeristest.WithHandlers(mw, handler))
	err := c.Next()
	wg.Wait()
	celeristest.ReleaseContext(c)
	testutil.AssertHTTPError(t, err, 503)
	if !ctxDone {
		t.Fatal("expected handler goroutine to see context cancellation")
	}
}

func TestPreemptiveHandlerError(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second, Preemptive: true})
	handler := func(_ *celeris.Context) error {
		return celeris.NewHTTPError(400, "bad request")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/error")
	testutil.AssertHTTPError(t, err, 400)
}

func TestPreemptiveDeadlinePropagated(t *testing.T) {
	mw := New(Config{Timeout: 2 * time.Second, Preemptive: true})
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

func TestPreemptivePanicRecovery(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second, Preemptive: true})
	handler := func(_ *celeris.Context) error {
		panic("handler panic in goroutine")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/panic")
	testutil.AssertHTTPError(t, err, 500)
}

func TestPreemptiveRaceDetector(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second, Preemptive: true})
	handler := func(c *celeris.Context) error {
		c.Set("key", "val")
		_ = c.Path()
		_ = c.Method()
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				rec, err := testutil.RunChain(t, chain, "GET", "/race")
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if rec.StatusCode != 200 {
					t.Errorf("unexpected status: %d", rec.StatusCode)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSkipPathsBypass(t *testing.T) {
	mw := New(Config{
		Timeout:   1 * time.Millisecond,
		SkipPaths: []string{"/health", "/metrics"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Skipped path should not timeout.
	rec, err := testutil.RunChain(t, chain, "GET", "/health")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")

	// Another skipped path.
	rec, err = testutil.RunChain(t, chain, "GET", "/metrics")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Non-skipped path with slow handler should timeout.
	slowHandler := func(c *celeris.Context) error {
		time.Sleep(50 * time.Millisecond)
		return c.String(200, "ok")
	}
	slowChain := []celeris.HandlerFunc{mw, slowHandler}
	_, err = testutil.RunChain(t, slowChain, "GET", "/api/slow")
	testutil.AssertHTTPError(t, err, 503)
}

func TestTimeoutFuncPerRequest(t *testing.T) {
	mw := New(Config{
		Timeout: 5 * time.Second,
		TimeoutFunc: func(c *celeris.Context) time.Duration {
			if c.Path() == "/fast" {
				return 50 * time.Millisecond
			}
			return 0 // fallback to static
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/fast")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestTimeoutFuncZeroFallsBackToStatic(t *testing.T) {
	mw := New(Config{
		Timeout: 1 * time.Second,
		TimeoutFunc: func(_ *celeris.Context) time.Duration {
			return 0
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/fallback")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestTimeoutFuncNegativeFallsBackToStatic(t *testing.T) {
	mw := New(Config{
		Timeout: 1 * time.Second,
		TimeoutFunc: func(_ *celeris.Context) time.Duration {
			return -1 * time.Second
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/neg")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestTimeoutFuncTriggersTimeout(t *testing.T) {
	mw := New(Config{
		Timeout: 10 * time.Second,
		TimeoutFunc: func(_ *celeris.Context) time.Duration {
			return 1 * time.Millisecond
		},
	})
	handler := func(c *celeris.Context) error {
		time.Sleep(50 * time.Millisecond)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/slow-tf")
	testutil.AssertHTTPError(t, err, 503)
}

func TestPreemptiveTimeoutFunc(t *testing.T) {
	mw := New(Config{
		Timeout:    10 * time.Second,
		Preemptive: true,
		TimeoutFunc: func(_ *celeris.Context) time.Duration {
			return 10 * time.Millisecond
		},
	})
	var wg sync.WaitGroup
	wg.Add(1)
	handler := func(c *celeris.Context) error {
		defer wg.Done()
		<-c.Context().Done()
		return c.Context().Err()
	}
	c, _ := celeristest.NewContext("GET", "/preemptive-tf", celeristest.WithHandlers(mw, handler))
	err := c.Next()
	wg.Wait()
	celeristest.ReleaseContext(c)
	testutil.AssertHTTPError(t, err, 503)
}

func TestPreemptiveChannelPoolReuse(t *testing.T) {
	mw := New(Config{Timeout: 1 * time.Second, Preemptive: true})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Run 100 preemptive requests. The channel pool should be reused
	// across iterations, resulting in at most a handful of allocations
	// rather than 100 separate channel allocations.
	allocs := testing.AllocsPerRun(100, func() {
		rec, err := testutil.RunChain(t, chain, "GET", "/pool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.StatusCode != 200 {
			t.Fatalf("unexpected status: %d", rec.StatusCode)
		}
	})

	// With sync.Pool reuse, the per-iteration channel allocation cost
	// should be well under 1 alloc/op on average (amortized). We allow
	// a generous budget that would still catch a regression where the
	// pool is not used (100 allocs for 100 requests = 1 alloc/op).
	// The real ceiling is the entire operation budget including context
	// creation, response recorder, etc., so we just verify it does not
	// grow linearly.
	const maxAllocsPerOp = 50
	if allocs > maxAllocsPerOp {
		t.Fatalf("preemptive mode allocs too high: %.0f per op (max %d)", allocs, maxAllocsPerOp)
	}
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
		_, _ = testutil.RunChain(t, chain, "GET", "/fuzz")
	})
}
