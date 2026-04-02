package bodylimit

import (
	"errors"
	"sync"
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func TestAutoSkipBodylessMethods(t *testing.T) {
	mw := New(Config{MaxBytes: 10})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	for _, method := range []string{"GET", "HEAD", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			chain := []celeris.HandlerFunc{mw, handler}
			rec, err := testutil.RunChain(t, chain, method, "/",
				celeristest.WithHeader("content-length", "999999"),
			)
			testutil.AssertNoError(t, err)
			testutil.AssertStatus(t, rec, 200)
		})
	}
}

func TestPOSTNotAutoSkipped(t *testing.T) {
	mw := New(Config{MaxBytes: 10})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/",
		celeristest.WithHeader("content-length", "999999"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestSkipPathsBodyLimit(t *testing.T) {
	mw := New(Config{
		MaxBytes:  10,
		SkipPaths: []string{"/upload/large"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload/large",
		celeristest.WithHeader("content-length", "999999"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestSkipPathsNonMatchStillChecks(t *testing.T) {
	mw := New(Config{
		MaxBytes:  10,
		SkipPaths: []string{"/upload/large"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload/small",
		celeristest.WithHeader("content-length", "999999"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestErrorHandlerContentLength(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		MaxBytes: 10,
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return celeris.NewHTTPError(429, "rate limited")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/",
		celeristest.WithHeader("content-length", "999999"),
	)
	testutil.AssertHTTPError(t, err, 429)
	if !errors.Is(receivedErr, ErrBodyTooLarge) {
		t.Fatalf("expected ErrBodyTooLarge, got %v", receivedErr)
	}
}

func TestErrorHandlerOnBodyBytes(t *testing.T) {
	var called bool
	mw := New(Config{
		MaxBytes: 10,
		ErrorHandler: func(_ *celeris.Context, _ error) error {
			called = true
			return celeris.NewHTTPError(413, "custom body too big")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	body := make([]byte, 20)
	_, err := testutil.RunChain(t, chain, "POST", "/",
		celeristest.WithBody(body),
	)
	testutil.AssertHTTPError(t, err, 413)
	if !called {
		t.Fatal("expected ErrorHandler to be called for body bytes check")
	}
}

func TestRequestUnderLimitPasses(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "512"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestRequestOverLimitReturns413(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "2048"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestRequestNoContentLengthPasses(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestRequestExactlyAtLimitPasses(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1024"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestRequestOneOverLimitRejects(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1025"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestCustomMaxBytes(t *testing.T) {
	mw := New(Config{MaxBytes: 100})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "200"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestSkipBypassesCheck(t *testing.T) {
	mw := New(Config{
		MaxBytes: 100,
		Skip:     func(_ *celeris.Context) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "skipped")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "999999"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "skipped")
}

func TestDefaultConfig4MB(t *testing.T) {
	if DefaultConfig.MaxBytes != 4*1024*1024 {
		t.Fatalf("default MaxBytes: got %d, want %d", DefaultConfig.MaxBytes, 4*1024*1024)
	}
}

func TestApplyDefaultsFixesZero(t *testing.T) {
	cfg := applyDefaults(Config{MaxBytes: 0})
	if cfg.MaxBytes != 4*1024*1024 {
		t.Fatalf("expected 4MB, got %d", cfg.MaxBytes)
	}
}

func TestApplyDefaultsFixesNegative(t *testing.T) {
	cfg := applyDefaults(Config{MaxBytes: -1})
	if cfg.MaxBytes != 4*1024*1024 {
		t.Fatalf("expected 4MB, got %d", cfg.MaxBytes)
	}
}

func TestZeroContentLengthPasses(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "0"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestDefaultConfigNoArgs(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "default")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1024"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestGETRequestPasses(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func FuzzBodyLimitContentLength(f *testing.F) {
	f.Add("0")
	f.Add("1024")
	f.Add("5000000")
	f.Add("-1")
	f.Add("abc")
	f.Add("")
	f.Fuzz(func(t *testing.T, cl string) {
		mw := New(Config{MaxBytes: 4096})
		handler := func(c *celeris.Context) error {
			return c.String(200, "ok")
		}
		chain := []celeris.HandlerFunc{mw, handler}
		opts := []celeristest.Option{}
		if cl != "" {
			opts = append(opts, celeristest.WithHeader("content-length", cl))
		}
		// Must not panic regardless of Content-Length value.
		_, _ = testutil.RunChain(t, chain, "POST", "/fuzz", opts...)
	})
}

func TestActualBodyOverLimit(t *testing.T) {
	mw := New(Config{MaxBytes: 10})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	body := make([]byte, 20)
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithBody(body),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestActualBodyUnderLimitPasses(t *testing.T) {
	mw := New(Config{MaxBytes: 100})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	body := make([]byte, 50)
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithBody(body),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestLyingContentLengthRejected(t *testing.T) {
	mw := New(Config{MaxBytes: 10})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	body := make([]byte, 20)
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithBody(body),
		celeristest.WithHeader("content-length", "5"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestNoContentLengthLargeBodyRejected(t *testing.T) {
	mw := New(Config{MaxBytes: 10})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	body := make([]byte, 20)
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithBody(body),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestLimitStringMB(t *testing.T) {
	mw := New(Config{Limit: "1MB"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1024"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestLimitStringKB(t *testing.T) {
	mw := New(Config{Limit: "10KB"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "20480"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestLimitStringFloat(t *testing.T) {
	mw := New(Config{Limit: "1.5MB"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1048576"), // 1MB exactly, under 1.5MB
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestLimitStringOverridesMaxBytes(t *testing.T) {
	mw := New(Config{Limit: "1KB", MaxBytes: 999999})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "2048"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestLimitStringInvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid Limit")
		}
	}()
	New(Config{Limit: "notasize"})
}

func TestLimitStringEmptyPanics(_ *testing.T) {
	// Empty Limit string should NOT panic — it means "use MaxBytes".
	// This is different from a non-empty invalid string.
	mw := New(Config{Limit: "", MaxBytes: 1024})
	_ = mw
}

func TestLimitStringB(t *testing.T) {
	mw := New(Config{Limit: "512B"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1024"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestLimitStringGB(t *testing.T) {
	mw := New(Config{Limit: "1GB"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1048576"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestLimitStringCaseInsensitive(t *testing.T) {
	mw := New(Config{Limit: "10mb"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1024"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestTBParsing(t *testing.T) {
	mw := New(Config{Limit: "1TB"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// 1GB is well under 1TB.
	rec, err := testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "1073741824"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// 2TB exceeds 1TB.
	_, err = testutil.RunChain(t, chain, "POST", "/upload",
		celeristest.WithHeader("content-length", "2199023255552"),
	)
	testutil.AssertHTTPError(t, err, 413)
}

func TestConcurrentBodyLimit(t *testing.T) {
	mw := New(Config{MaxBytes: 1024})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				rec, err := testutil.RunChain(t, chain, "POST", "/upload",
					celeristest.WithHeader("content-length", "512"))
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

func TestBodyLimitRejectNoExtraAlloc(t *testing.T) {
	mw := New(Config{MaxBytes: 512})
	// Measure baseline allocs from context setup alone.
	baseline := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			ctx, _ := celeristest.NewContext("POST", "/",
				celeristest.WithHeader("content-length", "1024"),
			)
			celeristest.ReleaseContext(ctx)
		}
	})
	// Measure allocs with middleware reject path.
	withMW := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			ctx, _ := celeristest.NewContext("POST", "/",
				celeristest.WithHeader("content-length", "1024"),
			)
			_ = mw(ctx)
			celeristest.ReleaseContext(ctx)
		}
	})
	// The middleware reject path should add at most 1 alloc (for the HTTPError).
	extra := withMW.AllocsPerOp() - baseline.AllocsPerOp()
	if extra > 1 {
		t.Fatalf("bodylimit reject: expected <=1 extra alloc over baseline, got %d (baseline=%d, total=%d)",
			extra, baseline.AllocsPerOp(), withMW.AllocsPerOp())
	}
}
