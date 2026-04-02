package cors

import (
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func okHandler(c *celeris.Context) error {
	return c.String(200, "ok")
}

func TestDefaultWildcardOrigin(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "*")
}

func TestSpecificOriginAllowed(t *testing.T) {
	mw := New(Config{AllowOrigins: []string{"http://foo.com", "http://bar.com"}})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://foo.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://foo.com")
}

func TestSpecificOriginDenied(t *testing.T) {
	mw := New(Config{AllowOrigins: []string{"http://foo.com"}})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://evil.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestNoOriginHeader(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestPreflightReturns204(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
}

func TestPreflightSetsAllowMethods(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeaderContains(t, rec, "access-control-allow-methods", "GET")
	testutil.AssertHeaderContains(t, rec, "access-control-allow-methods", "POST")
}

func TestPreflightSetsAllowHeaders(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeaderContains(t, rec, "access-control-allow-headers", "Content-Type")
	testutil.AssertHeaderContains(t, rec, "access-control-allow-headers", "Authorization")
}

func TestAllowCredentialsWithSpecificOrigin(t *testing.T) {
	mw := New(Config{
		AllowOrigins:     []string{"http://foo.com"},
		AllowCredentials: true,
	})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://foo.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-credentials", "true")
	testutil.AssertHeader(t, rec, "vary", "Origin")
}

func TestMaxAge(t *testing.T) {
	mw := New(Config{MaxAge: 3600})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-max-age", "3600")
}

func TestMaxAgeZeroOmitsHeader(t *testing.T) {
	mw := New(Config{MaxAge: 0})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-max-age")
}

func TestExposeHeaders(t *testing.T) {
	mw := New(Config{ExposeHeaders: []string{"X-Custom", "X-Total"}})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-expose-headers", "X-Custom, X-Total")
}

func TestExposeHeadersEmpty(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-expose-headers")
}

func TestSkipFunction(t *testing.T) {
	mw := New(Config{
		Skip: func(c *celeris.Context) bool {
			return c.Path() == "/health"
		},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/health",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestSkipFunctionAllowsNonSkipped(t *testing.T) {
	mw := New(Config{
		Skip: func(c *celeris.Context) bool {
			return c.Path() == "/health"
		},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "*")
}

func TestAllowCredentialsWithWildcardPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for AllowCredentials with wildcard")
		}
	}()
	New(Config{AllowCredentials: true})
}

func TestSimpleRequestCallsNext(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestPreflightDoesNotCallNext(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
	testutil.AssertBodyEmpty(t, rec)
}

func TestVaryHeaderSetForSpecificOrigin(t *testing.T) {
	mw := New(Config{AllowOrigins: []string{"http://a.com"}})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://a.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "vary", "Origin")
}

func TestVaryHeaderNotSetForWildcard(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "vary")
}

func TestCustomAllowMethods(t *testing.T) {
	mw := New(Config{AllowMethods: []string{"GET", "POST"}})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-methods", "GET, POST")
}

func TestCustomAllowHeaders(t *testing.T) {
	mw := New(Config{AllowHeaders: []string{"X-Custom"}})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-headers", "X-Custom")
}

func TestMultipleOriginsOnlyMatchesAllowed(t *testing.T) {
	mw := New(Config{AllowOrigins: []string{"http://a.com", "http://b.com"}})
	chain := []celeris.HandlerFunc{mw, okHandler}

	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://b.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://b.com")

	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://c.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestAllowOriginsFunc(t *testing.T) {
	mw := New(Config{
		AllowOrigins: []string{"http://static.com"},
		AllowOriginsFunc: func(origin string) bool {
			return origin == "http://dynamic.com"
		},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Static origin works.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://static.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://static.com")

	// Dynamic origin works.
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://dynamic.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://dynamic.com")

	// Neither.
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://evil.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestAllowOriginsFuncWithWildcardPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for AllowOriginsFunc with wildcard")
		}
	}()
	New(Config{
		AllowOriginsFunc: func(_ string) bool { return true },
	})
}

func TestSubdomainWildcard(t *testing.T) {
	mw := New(Config{
		AllowOrigins: []string{"https://*.example.com"},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}

	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "https://api.example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "https://api.example.com")

	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "https://evil.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestSubdomainWildcardRequiresSubdomain(t *testing.T) {
	mw := New(Config{
		AllowOrigins: []string{"https://*.example.com"},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Exact "https://.example.com" should not match (no subdomain).
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "https://.example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestMixedStaticAndWildcardOrigins(t *testing.T) {
	mw := New(Config{
		AllowOrigins: []string{"http://exact.com", "https://*.example.com"},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}

	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://exact.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://exact.com")

	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "https://sub.example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "https://sub.example.com")
}

func TestAllowPrivateNetwork(t *testing.T) {
	mw := New(Config{AllowPrivateNetwork: true})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"),
		celeristest.WithHeader("access-control-request-private-network", "true"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
	testutil.AssertHeader(t, rec, "access-control-allow-private-network", "true")
}

func TestPrivateNetworkNotSetWithoutRequest(t *testing.T) {
	mw := New(Config{AllowPrivateNetwork: true})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
	testutil.AssertNoHeader(t, rec, "access-control-allow-private-network")
}

func TestPrivateNetworkNotSetWhenDisabled(t *testing.T) {
	mw := New(Config{AllowPrivateNetwork: false})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"),
		celeristest.WithHeader("access-control-request-private-network", "true"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-private-network")
}

func TestPreflightDetectionRequiresACRM(t *testing.T) {
	mw := New()
	// OPTIONS without access-control-request-method is NOT a preflight.
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	// Should call next (okHandler) → 200, not 204 preflight.
	testutil.AssertStatus(t, rec, 200)
}

func TestPreflightWithACRM(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "POST"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
}

func TestPreflightVaryHeaders(t *testing.T) {
	mw := New(Config{AllowOrigins: []string{"http://a.com"}})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://a.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
	vary := rec.Header("vary")
	if vary == "" {
		t.Fatal("expected Vary header on preflight")
	}
	testutil.AssertHeaderContains(t, rec, "vary", "Access-Control-Request-Method")
	testutil.AssertHeaderContains(t, rec, "vary", "Access-Control-Request-Headers")
}

func TestPreflightVaryWithPrivateNetwork(t *testing.T) {
	mw := New(Config{AllowPrivateNetwork: true})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeaderContains(t, rec, "vary", "Access-Control-Request-Private-Network")
}

func TestOriginCheckOrder(t *testing.T) {
	funcCalled := false
	mw := New(Config{
		AllowOrigins: []string{"http://static.com", "https://*.wild.com"},
		AllowOriginsFunc: func(_ string) bool {
			funcCalled = true
			return true
		},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Static match — func should NOT be called.
	funcCalled = false
	_, _ = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://static.com"))
	if funcCalled {
		t.Fatal("expected AllowOriginsFunc NOT to be called for static match")
	}

	// Wildcard match — func should NOT be called.
	funcCalled = false
	_, _ = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "https://sub.wild.com"))
	if funcCalled {
		t.Fatal("expected AllowOriginsFunc NOT to be called for wildcard match")
	}

	// No match — func IS called.
	funcCalled = false
	_, _ = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://other.com"))
	if !funcCalled {
		t.Fatal("expected AllowOriginsFunc to be called for unmatched origin")
	}
}

func TestAllowOriginRequestFunc(t *testing.T) {
	mw := New(Config{
		AllowOrigins: []string{"http://static.com"},
		AllowOriginRequestFunc: func(c *celeris.Context, origin string) bool {
			return c.Header("x-tenant") == "acme" && origin == "http://tenant.com"
		},
	})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Static match (func not called).
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://static.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://static.com")

	// Request-func match.
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://tenant.com"),
		celeristest.WithHeader("x-tenant", "acme"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://tenant.com")

	// Request-func miss (wrong tenant).
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("origin", "http://tenant.com"),
		celeristest.WithHeader("x-tenant", "other"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")
}

func TestAllowOriginRequestFuncWithWildcardPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for AllowOriginRequestFunc with wildcard")
		}
	}()
	New(Config{
		AllowOriginRequestFunc: func(_ *celeris.Context, _ string) bool { return true },
	})
}

func FuzzOriginMatching(f *testing.F) {
	f.Add("http://example.com")
	f.Add("")
	f.Add("null")
	f.Add("http://evil.com")
	f.Add("http://example.com:8080")
	f.Fuzz(func(t *testing.T, origin string) {
		mw := New(Config{AllowOrigins: []string{"http://example.com"}})
		ctx, _ := celeristest.NewContextT(t, "GET", "/", celeristest.WithHeader("origin", origin))
		_ = mw(ctx)
	})
}

func TestVaryHeaderOnNonPreflight(t *testing.T) {
	mw := New(Config{AllowOrigins: []string{"http://a.com"}})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Non-preflight GET with specific origin should set Vary: Origin.
	rec, err := testutil.RunChain(t, chain, "GET", "/api/data",
		celeristest.WithHeader("origin", "http://a.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertHeader(t, rec, "vary", "Origin")
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "http://a.com")

	// POST non-preflight should also set Vary: Origin.
	rec, err = testutil.RunChain(t, chain, "POST", "/api/data",
		celeristest.WithHeader("origin", "http://a.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertHeader(t, rec, "vary", "Origin")

	// Denied origin should not set Vary.
	rec, err = testutil.RunChain(t, chain, "GET", "/api/data",
		celeristest.WithHeader("origin", "http://evil.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "vary")
}

func TestSkipPaths(t *testing.T) {
	mw := New(Config{SkipPaths: []string{"/health", "/ready"}})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Skipped path: no CORS headers.
	rec, err := testutil.RunChain(t, chain, "GET", "/health",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")

	// Skipped path: no CORS headers.
	rec, err = testutil.RunChain(t, chain, "GET", "/ready",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertNoHeader(t, rec, "access-control-allow-origin")

	// Non-skipped path: CORS headers present.
	rec, err = testutil.RunChain(t, chain, "GET", "/api/data",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-origin", "*")
}

func TestSkipPathsWithPreflight(t *testing.T) {
	mw := New(Config{SkipPaths: []string{"/health"}})
	chain := []celeris.HandlerFunc{mw, okHandler}

	// Skipped path: preflight should pass through.
	rec, err := testutil.RunChain(t, chain, "OPTIONS", "/health",
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("access-control-request-method", "GET"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertNoHeader(t, rec, "access-control-allow-methods")
}

func FuzzHeaderValues(f *testing.F) {
	f.Add("X-Custom")
	f.Add("")
	f.Add("X-A, X-B, X-C")
	f.Fuzz(func(t *testing.T, header string) {
		if header == "" {
			return
		}
		mw := New(Config{AllowHeaders: []string{header}})
		ctx, _ := celeristest.NewContextT(t, "OPTIONS", "/", celeristest.WithHeader("origin", "http://example.com"))
		_ = mw(ctx)
	})
}
