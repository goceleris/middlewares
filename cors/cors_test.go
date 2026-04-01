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
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 204)
}

func TestPreflightSetsAllowMethods(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeaderContains(t, rec, "access-control-allow-methods", "GET")
	testutil.AssertHeaderContains(t, rec, "access-control-allow-methods", "POST")
}

func TestPreflightSetsAllowHeaders(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"))
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
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-max-age", "3600")
}

func TestMaxAgeZeroOmitsHeader(t *testing.T) {
	mw := New(Config{MaxAge: 0})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"))
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
		celeristest.WithHeader("origin", "http://example.com"))
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
		celeristest.WithHeader("origin", "http://example.com"))
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "access-control-allow-methods", "GET, POST")
}

func TestCustomAllowHeaders(t *testing.T) {
	mw := New(Config{AllowHeaders: []string{"X-Custom"}})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "OPTIONS", "/",
		celeristest.WithHeader("origin", "http://example.com"))
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
