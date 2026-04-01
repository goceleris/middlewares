package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"
	"github.com/goceleris/middlewares/internal/testutil"
)

func okHandler(c *celeris.Context) error {
	return c.String(200, "ok")
}

func contextHeader(c *celeris.Context, key string) string {
	for _, h := range c.ResponseHeaders() {
		if h[0] == key {
			return h[1]
		}
	}
	return ""
}

func TestAllowUnderLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 100, Burst: 5, CleanupInterval: time.Hour, CleanupContext: ctx})

	for range 5 {
		_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
		testutil.AssertNoError(t, err)
	}
}

func TestBlockOverLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 3, CleanupInterval: time.Hour, CleanupContext: ctx})

	// Consume all 3 tokens.
	for range 3 {
		_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "10.0.0.1"))
		testutil.AssertNoError(t, err)
	}

	// 4th request should be blocked.
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "10.0.0.1"))
	testutil.AssertHTTPError(t, err, 429)
}

func TestRateLimitHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 100, Burst: 10, CleanupInterval: time.Hour, CleanupContext: ctx})

	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "x-ratelimit-limit", "10")
	testutil.AssertHeader(t, rec, "x-ratelimit-remaining", "9")

	got := rec.Header("x-ratelimit-reset")
	if got == "" {
		t.Fatal("x-ratelimit-reset header missing")
	}
}

func TestHeadersOnDeny(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 1, CleanupInterval: time.Hour, CleanupContext: ctx})

	// Exhaust the single token.
	_, _ = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))

	// Denied request: middleware returns error before c.Next(), so headers are on context but not flushed to recorder.
	c, _ := celeristest.NewContextT(t, "GET", "/", celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	err := mw(c)
	testutil.AssertHTTPError(t, err, 429)

	if got := contextHeader(c, "x-ratelimit-limit"); got != "1" {
		t.Fatalf("x-ratelimit-limit: got %q, want %q", got, "1")
	}
	if got := contextHeader(c, "x-ratelimit-remaining"); got != "0" {
		t.Fatalf("x-ratelimit-remaining: got %q, want %q", got, "0")
	}
}

func TestDifferentKeysGetSeparateBuckets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 1, CleanupInterval: time.Hour, CleanupContext: ctx})

	// IP A uses its token.
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "10.0.0.1"))
	testutil.AssertNoError(t, err)

	// IP A is now blocked.
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "10.0.0.1"))
	testutil.AssertHTTPError(t, err, 429)

	// IP B should still be allowed (separate bucket).
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "10.0.0.2"))
	testutil.AssertNoError(t, err)
}

func TestSkipPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{
		RPS:             0.001,
		Burst:           1,
		SkipPaths:       []string{"/health"},
		CleanupInterval: time.Hour,
		CleanupContext:  ctx,
	})

	// Exhaust tokens on default path.
	_, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/", celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	_, err = testutil.RunMiddlewareWithMethod(t, mw, "GET", "/", celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertHTTPError(t, err, 429)

	// /health should bypass rate limiting entirely (no headers set on context).
	c, _ := celeristest.NewContextT(t, "GET", "/health", celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	err = mw(c)
	testutil.AssertNoError(t, err)
	if got := contextHeader(c, "x-ratelimit-limit"); got != "" {
		t.Fatalf("expected no x-ratelimit-limit on skipped path, got %q", got)
	}
}

func TestSkipFunction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{
		RPS:   0.001,
		Burst: 1,
		Skip: func(c *celeris.Context) bool {
			return c.Header("x-internal") == "true"
		},
		CleanupInterval: time.Hour,
		CleanupContext:  ctx,
	})

	// Exhaust tokens.
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertHTTPError(t, err, 429)

	// Skipped request should pass through (no headers set).
	c, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHeader("x-forwarded-for", "1.2.3.4"),
		celeristest.WithHeader("x-internal", "true"),
	)
	err = mw(c)
	testutil.AssertNoError(t, err)
	if got := contextHeader(c, "x-ratelimit-limit"); got != "" {
		t.Fatalf("expected no x-ratelimit-limit on skipped request, got %q", got)
	}
}

func TestTokenRefill(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 1000 RPS = 1 token per ms, burst of 1.
	mw := New(Config{RPS: 1000, Burst: 1, CleanupInterval: time.Hour, CleanupContext: ctx})

	// Use the token.
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)

	// Should be blocked now.
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertHTTPError(t, err, 429)

	// Wait for refill (at 1000 RPS, 5ms gives ~5 tokens).
	time.Sleep(5 * time.Millisecond)

	// Should be allowed again.
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
}

func TestCustomKeyFunc(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{
		RPS:   0.001,
		Burst: 1,
		KeyFunc: func(c *celeris.Context) string {
			return c.Header("x-api-key")
		},
		CleanupInterval: time.Hour,
		CleanupContext:  ctx,
	})

	// Key "abc" uses its token.
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-api-key", "abc"))
	testutil.AssertNoError(t, err)

	// Key "abc" is blocked.
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-api-key", "abc"))
	testutil.AssertHTTPError(t, err, 429)

	// Key "xyz" is separate, should be allowed.
	_, err = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-api-key", "xyz"))
	testutil.AssertNoError(t, err)
}

func TestCustomBurstAndRPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 5, CleanupInterval: time.Hour, CleanupContext: ctx})

	// Should allow exactly 5 requests.
	for range 5 {
		_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
		testutil.AssertNoError(t, err)
	}

	// 6th should fail.
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertHTTPError(t, err, 429)
}

func TestHTTP429Error(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 1, CleanupInterval: time.Hour, CleanupContext: ctx})

	_, _ = testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertError(t, err)
	testutil.AssertHTTPError(t, err, 429)
}

func TestConcurrentAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 10, CleanupInterval: time.Hour, CleanupContext: ctx})

	var (
		wg       sync.WaitGroup
		allowed  atomic.Int64
		rejected atomic.Int64
	)

	const goroutines = 50
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			c, _ := celeristest.NewContext("GET", "/", celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
			err := mw(c)
			celeristest.ReleaseContext(c)
			if err != nil {
				rejected.Add(1)
			} else {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	a := allowed.Load()
	r := rejected.Load()
	if a+r != goroutines {
		t.Fatalf("total requests: got %d, want %d", a+r, goroutines)
	}
	if a > 10 {
		t.Fatalf("allowed %d requests, expected <= 10 (burst)", a)
	}
	if a < 1 {
		t.Fatal("expected at least 1 allowed request")
	}
}

func TestDefaultConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{CleanupContext: ctx})

	// Default burst is 20, should allow 20 requests.
	for range 20 {
		_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
		testutil.AssertNoError(t, err)
	}
}

func TestRemainingDecreases(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mw := New(Config{RPS: 0.001, Burst: 3, CleanupInterval: time.Hour, CleanupContext: ctx})

	chain := []celeris.HandlerFunc{mw, okHandler}

	// First request: remaining should be burst-1 = 2.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "x-ratelimit-remaining", "2")

	// Second: remaining = 1.
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "x-ratelimit-remaining", "1")

	// Third: remaining = 0.
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "x-ratelimit-remaining", "0")
}

func TestValidatePanicsOnInvalidBurst(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for Burst < 1")
		}
	}()
	// Call validate directly with Burst=0 (bypassing applyDefaults which would fix it).
	cfg := Config{Burst: 0, RPS: 1}
	cfg.validate()
}

func TestCleanupContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	// Should not panic or hang.
	mw := New(Config{RPS: 10, Burst: 10, CleanupInterval: time.Millisecond, CleanupContext: ctx})
	_, err := testutil.RunMiddleware(t, mw, celeristest.WithHeader("x-forwarded-for", "1.2.3.4"))
	testutil.AssertNoError(t, err)
}

func TestNextPow2(t *testing.T) {
	cases := [][2]int{{0, 1}, {1, 1}, {2, 2}, {3, 4}, {4, 4}, {5, 8}, {7, 8}, {8, 8}, {9, 16}}
	for _, tc := range cases {
		got := nextPow2(tc[0])
		if got != tc[1] {
			t.Errorf("nextPow2(%d) = %d, want %d", tc[0], got, tc[1])
		}
	}
}

func TestFnv1aDeterministic(t *testing.T) {
	a := fnv1a("test-key")
	b := fnv1a("test-key")
	if a != b {
		t.Fatalf("fnv1a not deterministic: %d != %d", a, b)
	}
	c := fnv1a("different-key")
	if a == c {
		t.Fatal("fnv1a collision on different keys")
	}
}

func TestFormatResetSeconds(t *testing.T) {
	now := int64(0)
	reset := int64(time.Second) // 1 second ahead
	got := formatResetSeconds(reset, now)
	if got != "1" {
		t.Fatalf("formatResetSeconds: got %q, want %q", got, "1")
	}

	// Negative (reset in the past) should clamp to 0.
	got = formatResetSeconds(now, reset)
	if got != "0" {
		t.Fatalf("formatResetSeconds negative: got %q, want %q", got, "0")
	}
}

func FuzzKeyExtraction(f *testing.F) {
	f.Add("192.168.1.1")
	f.Add("")
	f.Add("::1")
	f.Add("very-long-key-" + string(make([]byte, 1000)))

	ctx, cancel := context.WithCancel(context.Background())
	f.Cleanup(cancel)
	mw := New(Config{RPS: 1e9, Burst: 1e9, CleanupInterval: time.Hour, CleanupContext: ctx})

	f.Fuzz(func(_ *testing.T, ip string) {
		c, _ := celeristest.NewContext("GET", "/", celeristest.WithHeader("x-forwarded-for", ip))
		_ = mw(c)
		celeristest.ReleaseContext(c)
	})
}

func FuzzConcurrentAccess(f *testing.F) {
	f.Add("key1", 5)
	f.Add("key2", 10)
	f.Add("", 1)

	ctx, cancel := context.WithCancel(context.Background())
	f.Cleanup(cancel)
	l := newShardedLimiter(ctx, 4, 1e6, 1e6, time.Hour)

	f.Fuzz(func(_ *testing.T, key string, n int) {
		if n < 1 || n > 100 {
			return
		}
		now := time.Now().UnixNano()
		var wg sync.WaitGroup
		wg.Add(n)
		for range n {
			go func() {
				defer wg.Done()
				l.allow(key, now)
			}()
		}
		wg.Wait()
	})
}
