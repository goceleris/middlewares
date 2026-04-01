package bodylimit

import (
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

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
		Skip:     func(c *celeris.Context) bool { return true },
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
