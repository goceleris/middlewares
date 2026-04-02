package csrf

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func TestSafeMethodGeneratesToken(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token == "" {
		t.Fatal("expected non-empty CSRF token in context")
	}
	if len(token) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Fatalf("token length: got %d, want 64", len(token))
	}
}

func TestSafeMethodSetsCookie(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)

	found := false
	for _, h := range rec.Headers {
		if h[0] == "set-cookie" {
			found = true
			if len(h[1]) == 0 {
				t.Fatal("set-cookie header is empty")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected set-cookie header for CSRF token")
	}
}

func TestSafeMethodReusesExistingCookie(t *testing.T) {
	existing := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("_csrf", existing),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token != existing {
		t.Fatalf("expected reused token %q, got %q", existing, token)
	}
	// Cookie should be re-set with the same value.
	found := false
	for _, h := range rec.Headers {
		if h[0] == "set-cookie" && containsSubstring(h[1], existing) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected set-cookie with existing token value")
	}
}

func TestSafeMethodGeneratesNewTokenWhenNoCookie(t *testing.T) {
	mw := New()
	var token1, token2 string
	handler1 := func(c *celeris.Context) error {
		token1 = TokenFromContext(c)
		return nil
	}
	handler2 := func(c *celeris.Context) error {
		token2 = TokenFromContext(c)
		return nil
	}
	chain1 := []celeris.HandlerFunc{mw, handler1}
	chain2 := []celeris.HandlerFunc{mw, handler2}
	_, err := testutil.RunChain(t, chain1, "GET", "/")
	testutil.AssertNoError(t, err)
	_, err = testutil.RunChain(t, chain2, "GET", "/")
	testutil.AssertNoError(t, err)
	if token1 == "" || token2 == "" {
		t.Fatal("expected non-empty tokens")
	}
	if token1 == token2 {
		t.Fatal("expected different tokens for requests without cookies")
	}
}

func TestHEADMethodIsSafe(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return nil
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "HEAD", "/")
	testutil.AssertNoError(t, err)
	if token == "" {
		t.Fatal("expected token for HEAD request")
	}
}

func TestOPTIONSMethodIsSafe(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return nil
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "OPTIONS", "/")
	testutil.AssertNoError(t, err)
	if token == "" {
		t.Fatal("expected token for OPTIONS request")
	}
}

func TestUnsafeMethodValidatesToken(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	var stored string
	handler := func(c *celeris.Context) error {
		stored = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if stored != token {
		t.Fatalf("context token: got %q, want %q", stored, token)
	}
}

func TestUnsafeMethodMissingCookie(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", "sometoken"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestUnsafeMethodMissingHeader(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", "sometoken"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestUnsafeMethodTokenMismatch(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", "aaaa"),
		celeristest.WithCookie("_csrf", "bbbb"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestPUTMethodIsUnsafe(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "PUT", "/resource",
		celeristest.WithCookie("_csrf", "tok"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestDELETEMethodIsUnsafe(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "DELETE", "/resource")
	testutil.AssertHTTPError(t, err, 403)
}

func TestPATCHMethodIsUnsafe(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "PATCH", "/resource")
	testutil.AssertHTTPError(t, err, 403)
}

func TestTokenFromContextNoToken(t *testing.T) {
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	if got := TokenFromContext(ctx); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestTokenFromContextWithToken(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/")
	if token == "" {
		t.Fatal("expected non-empty token from TokenFromContext")
	}
}

func TestFormTokenLookup(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{TokenLookup: "form:_csrf"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", token),
		celeristest.WithContentType("application/x-www-form-urlencoded"),
		celeristest.WithBody([]byte("_csrf="+token)),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestQueryTokenLookup(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{TokenLookup: "query:csrf_token"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", token),
		celeristest.WithQuery("csrf_token", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestQueryTokenLookupMissing(t *testing.T) {
	mw := New(Config{TokenLookup: "query:csrf_token"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", "sometoken"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestSkipFunction(t *testing.T) {
	mw := New(Config{
		Skip: func(_ *celeris.Context) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "skipped")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "skipped")
}

func TestSkipPaths(t *testing.T) {
	mw := New(Config{SkipPaths: []string{"/health", "/ready"}})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	rec, err := testutil.RunChain(t, chain, "POST", "/health")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	rec, err = testutil.RunChain(t, chain, "POST", "/ready")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	_, err = testutil.RunChain(t, chain, "POST", "/other")
	testutil.AssertHTTPError(t, err, 403)
}

func TestCustomErrorHandler(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return celeris.NewHTTPError(418, "custom error")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit")
	testutil.AssertHTTPError(t, err, 418)
	if receivedErr == nil {
		t.Fatal("expected ErrorHandler to receive an error")
	}
}

func TestCustomErrorHandlerOnMismatch(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return celeris.NewHTTPError(418, "mismatch")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", "aaa"),
		celeristest.WithCookie("_csrf", "bbb"),
	)
	testutil.AssertHTTPError(t, err, 418)
	if receivedErr != ErrForbidden {
		t.Fatalf("expected ErrForbidden, got %v", receivedErr)
	}
}

func TestCookieOptionsAreSet(t *testing.T) {
	mw := New(Config{
		CookieName:     "my_csrf",
		CookiePath:     "/app",
		CookieDomain:   "example.com",
		CookieMaxAge:   3600,
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: celeris.SameSiteStrictMode,
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	found := false
	for _, h := range rec.Headers {
		if h[0] == "set-cookie" {
			found = true
			v := h[1]
			if !containsSubstring(v, "my_csrf=") {
				t.Fatalf("cookie name not found in set-cookie: %s", v)
			}
			if !containsSubstring(v, "Path=/app") {
				t.Fatalf("cookie path not found in set-cookie: %s", v)
			}
			if !containsSubstring(v, "Domain=example.com") {
				t.Fatalf("cookie domain not found in set-cookie: %s", v)
			}
			if !containsSubstring(v, "Max-Age=3600") {
				t.Fatalf("cookie max-age not found in set-cookie: %s", v)
			}
			if !containsSubstring(v, "Secure") {
				t.Fatalf("cookie Secure not found in set-cookie: %s", v)
			}
			if !containsSubstring(v, "HttpOnly") {
				t.Fatalf("cookie HttpOnly not found in set-cookie: %s", v)
			}
			if !containsSubstring(v, "SameSite=Strict") {
				t.Fatalf("cookie SameSite=Strict not found in set-cookie: %s", v)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected set-cookie header")
	}
}

func TestDefaultConfigValues(t *testing.T) {
	if DefaultConfig.TokenLength != 32 {
		t.Fatalf("TokenLength: got %d, want 32", DefaultConfig.TokenLength)
	}
	if DefaultConfig.TokenLookup != "header:X-CSRF-Token" {
		t.Fatalf("TokenLookup: got %q, want %q", DefaultConfig.TokenLookup, "header:X-CSRF-Token")
	}
	if DefaultConfig.CookieName != "_csrf" {
		t.Fatalf("CookieName: got %q, want %q", DefaultConfig.CookieName, "_csrf")
	}
	if DefaultConfig.CookiePath != "/" {
		t.Fatalf("CookiePath: got %q, want %q", DefaultConfig.CookiePath, "/")
	}
	if DefaultConfig.CookieMaxAge != 86400 {
		t.Fatalf("CookieMaxAge: got %d, want 86400", DefaultConfig.CookieMaxAge)
	}
	if !DefaultConfig.CookieHTTPOnly {
		t.Fatal("CookieHTTPOnly: expected true")
	}
	if DefaultConfig.CookieSameSite != celeris.SameSiteLaxMode {
		t.Fatalf("CookieSameSite: got %v, want SameSiteLaxMode", DefaultConfig.CookieSameSite)
	}
	if DefaultConfig.Expiration != time.Hour {
		t.Fatalf("Expiration: got %v, want 1h", DefaultConfig.Expiration)
	}
	if DefaultConfig.ContextKey != "csrf_token" {
		t.Fatalf("ContextKey: got %q, want %q", DefaultConfig.ContextKey, "csrf_token")
	}
}

func TestContextKeyConstant(t *testing.T) {
	if ContextKey != "csrf_token" {
		t.Fatalf("ContextKey: got %q, want %q", ContextKey, "csrf_token")
	}
}

func TestInvalidTokenLookupFormatPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid TokenLookup format")
		}
	}()
	New(Config{TokenLookup: "invalid"})
}

func TestInvalidTokenLookupSourcePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for unsupported TokenLookup source")
		}
	}()
	New(Config{TokenLookup: "cookie:token"})
}

func TestQueryTokenLookupIsValid(t *testing.T) {
	// query: should not panic (it's now supported).
	_ = New(Config{TokenLookup: "query:token"})
}

func TestApplyDefaultsFixesZeroTokenLength(t *testing.T) {
	cfg := applyDefaults(Config{TokenLength: 0})
	if cfg.TokenLength != 32 {
		t.Fatalf("expected 32, got %d", cfg.TokenLength)
	}
}

func TestApplyDefaultsFixesNegativeTokenLength(t *testing.T) {
	cfg := applyDefaults(Config{TokenLength: -5})
	if cfg.TokenLength != 32 {
		t.Fatalf("expected 32, got %d", cfg.TokenLength)
	}
}

func TestApplyDefaultsPreservesCustomValues(t *testing.T) {
	cfg := applyDefaults(Config{
		TokenLength:  16,
		TokenLookup:  "form:csrf_tok",
		CookieName:   "my_tok",
		CookiePath:   "/api",
		CookieMaxAge: 7200,
	})
	if cfg.TokenLength != 16 {
		t.Fatalf("TokenLength: got %d, want 16", cfg.TokenLength)
	}
	if cfg.TokenLookup != "form:csrf_tok" {
		t.Fatalf("TokenLookup: got %q", cfg.TokenLookup)
	}
	if cfg.CookieName != "my_tok" {
		t.Fatalf("CookieName: got %q", cfg.CookieName)
	}
	if cfg.CookiePath != "/api" {
		t.Fatalf("CookiePath: got %q", cfg.CookiePath)
	}
	if cfg.CookieMaxAge != 7200 {
		t.Fatalf("CookieMaxAge: got %d", cfg.CookieMaxAge)
	}
}

func TestApplyDefaultsIndependentFields(t *testing.T) {
	// Setting CookieSameSite alone should not prevent SafeMethods from getting defaults.
	cfg := applyDefaults(Config{
		CookieSameSite: celeris.SameSiteStrictMode,
	})
	if len(cfg.SafeMethods) == 0 {
		t.Fatal("SafeMethods should be defaulted independently")
	}
	if cfg.CookieSameSite != celeris.SameSiteStrictMode {
		t.Fatalf("CookieSameSite: got %v, want SameSiteStrictMode", cfg.CookieSameSite)
	}
	if !cfg.CookieHTTPOnly {
		t.Fatal("CookieHTTPOnly should default to true")
	}
}

func TestApplyDefaultsDisableCookieHTTPOnly(t *testing.T) {
	cfg := applyDefaults(Config{
		DisableCookieHTTPOnly: true,
	})
	if cfg.CookieHTTPOnly {
		t.Fatal("CookieHTTPOnly should be false when DisableCookieHTTPOnly is set")
	}
}

func TestGenerateTokenLength(t *testing.T) {
	tok := generateToken(16)
	if len(tok) != 32 {
		t.Fatalf("expected 32 hex chars for 16 bytes, got %d", len(tok))
	}
	tok = generateToken(32)
	if len(tok) != 64 {
		t.Fatalf("expected 64 hex chars for 32 bytes, got %d", len(tok))
	}
}

func TestGenerateTokenUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		tok := generateToken(32)
		if _, ok := seen[tok]; ok {
			t.Fatal("generated duplicate token")
		}
		seen[tok] = struct{}{}
	}
}

func TestTRACEMethodIsSafe(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return nil
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "TRACE", "/")
	testutil.AssertNoError(t, err)
	if token == "" {
		t.Fatal("expected token for TRACE request")
	}
}

func TestCustomSafeMethods(t *testing.T) {
	mw := New(Config{SafeMethods: []string{"GET"}})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// GET is still safe.
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// HEAD is no longer safe (not in custom list).
	_, err = testutil.RunChain(t, chain, "HEAD", "/")
	testutil.AssertHTTPError(t, err, 403)
}

func TestVaryCookieHeaderOnSafeMethod(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "vary", "Cookie")
}

func TestVaryCookieHeaderOnUnsafeMethod(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertHeader(t, rec, "vary", "Cookie")
}

func TestSecFetchSiteCrossSiteRejected(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("sec-fetch-site", "cross-site"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestSecFetchSiteSameOriginAllowed(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("sec-fetch-site", "same-origin"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestOriginMismatchRejected(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// Default :authority is "localhost", origin is different.
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://evil.com"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestOriginMatchAllowed(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// :authority defaults to "localhost" in celeristest.
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://localhost"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestOriginNoHeaderAllowed(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestTrustedOriginsAllowed(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{
		TrustedOrigins: []string{"https://trusted.example.com"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://trusted.example.com"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestTrustedOriginsUnlistedRejected(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{
		TrustedOrigins: []string{"https://trusted.example.com"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://untrusted.example.com"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestSecFetchSiteWithErrorHandler(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return celeris.NewHTTPError(418, "custom")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("sec-fetch-site", "cross-site"),
	)
	testutil.AssertHTTPError(t, err, 418)
	if !errors.Is(receivedErr, ErrSecFetchSite) {
		t.Fatalf("expected ErrSecFetchSite, got %v", receivedErr)
	}
}

func TestOriginMismatchWithErrorHandler(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return celeris.NewHTTPError(418, "custom")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("origin", "https://evil.com"),
	)
	testutil.AssertHTTPError(t, err, 418)
	if !errors.Is(receivedErr, ErrOriginMismatch) {
		t.Fatalf("expected ErrOriginMismatch, got %v", receivedErr)
	}
}

func TestIsOriginAllowed(t *testing.T) {
	trusted := map[string]struct{}{
		"https://app.example.com": {},
	}
	tests := []struct {
		name    string
		origin  string
		host    string
		allowed bool
	}{
		{"same host", "https://localhost", "localhost", true},
		{"same host with port", "https://localhost:8080", "localhost:8080", true},
		{"trusted origin", "https://app.example.com", "localhost", true},
		{"untrusted origin", "https://evil.com", "localhost", false},
		{"empty origin host", "data:text/html", "localhost", false},
		{"invalid origin", "://bad", "localhost", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOriginAllowed(tt.origin, tt.host, trusted, nil)
			if got != tt.allowed {
				t.Fatalf("isOriginAllowed(%q, %q): got %v, want %v", tt.origin, tt.host, got, tt.allowed)
			}
		})
	}
}

func TestTokenLengthExceeds32Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for TokenLength > 32")
		}
	}()
	New(Config{TokenLength: 33})
}

func TestSameSiteNoneWithoutSecurePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for SameSite=None without Secure")
		}
	}()
	New(Config{
		CookieSameSite: celeris.SameSiteNoneMode,
		CookieSecure:   false,
	})
}

func TestSameSiteNoneWithSecureOk(t *testing.T) {
	// Should not panic.
	_ = New(Config{
		CookieSameSite: celeris.SameSiteNoneMode,
		CookieSecure:   true,
	})
}

func TestVaryHeaderDoesNotClobber(t *testing.T) {
	mw := New()
	// Set a Vary header before the CSRF middleware runs.
	preMiddleware := func(c *celeris.Context) error {
		c.AddHeader("vary", "Accept-Encoding")
		return c.Next()
	}
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{preMiddleware, mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Both Vary values must be present as separate header entries.
	foundEncoding := false
	foundCookie := false
	for _, h := range rec.Headers {
		if h[0] == "vary" && h[1] == "Accept-Encoding" {
			foundEncoding = true
		}
		if h[0] == "vary" && h[1] == "Cookie" {
			foundCookie = true
		}
	}
	if !foundEncoding {
		t.Fatal("expected Vary: Accept-Encoding to be preserved")
	}
	if !foundCookie {
		t.Fatal("expected Vary: Cookie to be added")
	}
}

func TestRefererFallbackHTTPS(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// HTTPS request with mismatched Referer and no Origin should be rejected.
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("x-forwarded-proto", "https"),
		celeristest.WithHeader("referer", "https://evil.com/page"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestRefererFallbackHTTPSMatchingHost(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// HTTPS request with matching Referer and no Origin should pass.
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("x-forwarded-proto", "https"),
		celeristest.WithHeader("referer", "https://localhost/page"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestRefererFallbackSkippedOnHTTP(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// HTTP request (default) with mismatched Referer: referer check skipped.
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("referer", "https://evil.com/page"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

// --- Storage (server-side token) tests ---

func TestStorageSafeMethodStoresToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	mw := New(Config{Storage: store})
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token == "" {
		t.Fatal("expected token")
	}
	// Token should be in storage.
	stored, ok := store.Get(token)
	if !ok {
		t.Fatal("token not found in storage")
	}
	if stored != token {
		t.Fatalf("stored token %q != context token %q", stored, token)
	}
}

func TestStorageUnsafeMethodValidates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	store.Set(token, token, time.Hour)
	mw := New(Config{Storage: store})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestStorageUnsafeMethodRejectsExpiredToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	// Store with a past expiry.
	store.Set(token, token, time.Nanosecond)
	time.Sleep(time.Millisecond)
	mw := New(Config{Storage: store})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestStorageUnsafeMethodRejectsMissingStorageToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	// Token in cookie but NOT in storage.
	mw := New(Config{Storage: store})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestStorageUnsafeMethodRejectsMismatchedRequestToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	store.Set(token, token, time.Hour)
	mw := New(Config{Storage: store})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", "wrong"),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestStorageSafeMethodRegeneratesWhenNotInStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	mw := New(Config{Storage: store})
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	oldCookie := "stale_cookie_value"
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("_csrf", oldCookie),
	)
	testutil.AssertNoError(t, err)
	// Token should NOT be the stale cookie since it's not in storage.
	if token == oldCookie {
		t.Fatal("expected new token, got stale cookie value")
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

// --- SingleUseToken tests ---

func TestSingleUseTokenDeletesAfterValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	store.Set(token, token, time.Hour)
	mw := New(Config{Storage: store, SingleUseToken: true})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// First request: succeeds.
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Token should be deleted from storage.
	_, ok := store.Get(token)
	if ok {
		t.Fatal("expected token to be deleted from storage after single use")
	}

	// Second request with same token: fails.
	_, err = testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestSingleUseTokenWithoutStoragePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for SingleUseToken without Storage")
		}
	}()
	New(Config{SingleUseToken: true})
}

// --- Wildcard TrustedOrigins tests ---

func TestWildcardTrustedOriginAllowed(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{
		TrustedOrigins: []string{"https://*.example.com"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://app.example.com"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestWildcardTrustedOriginDeepSubdomain(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{
		TrustedOrigins: []string{"https://*.example.com"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://deep.sub.example.com"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestWildcardTrustedOriginNoMatchRejected(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{
		TrustedOrigins: []string{"https://*.example.com"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://evil.com"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestWildcardTrustedOriginMixedWithExact(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{
		TrustedOrigins: []string{
			"https://exact.example.com",
			"https://*.wildcard.com",
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Exact match.
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://exact.example.com"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Wildcard match.
	rec, err = testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://sub.wildcard.com"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestWildcardOriginMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern wildcardOrigin
		origin  string
		want    bool
	}{
		{"match", wildcardOrigin{"https://", ".example.com"}, "https://app.example.com", true},
		{"no match", wildcardOrigin{"https://", ".example.com"}, "https://evil.com", false},
		{"too short", wildcardOrigin{"https://", ".example.com"}, "https://.example.com", false},
		{"deep sub", wildcardOrigin{"https://", ".example.com"}, "https://a.b.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pattern.match(tt.origin)
			if got != tt.want {
				t.Fatalf("match(%q): got %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

// --- Multiple extractors (comma-separated TokenLookup) tests ---

func TestMultipleExtractorsHeaderFirst(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{TokenLookup: "header:X-CSRF-Token,form:_csrf"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestMultipleExtractorsFormFallback(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{TokenLookup: "header:X-CSRF-Token,form:_csrf"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", token),
		celeristest.WithContentType("application/x-www-form-urlencoded"),
		celeristest.WithBody([]byte("_csrf="+token)),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestMultipleExtractorsAllMissing(t *testing.T) {
	mw := New(Config{TokenLookup: "header:X-CSRF-Token,form:_csrf,query:token"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", "sometoken"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestMultipleExtractorsThreeSourcesQueryLast(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New(Config{TokenLookup: "header:X-CSRF-Token,form:_csrf,query:token"})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithCookie("_csrf", token),
		celeristest.WithQuery("token", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestMultipleExtractorsInvalidSegmentPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid segment in multi-extractor")
		}
	}()
	New(Config{TokenLookup: "header:X-CSRF-Token,bad"})
}

// --- Custom KeyGenerator tests ---

func TestCustomKeyGenerator(t *testing.T) {
	var counter atomic.Int32
	mw := New(Config{
		KeyGenerator: func() string {
			counter.Add(1)
			return "custom-token-value"
		},
	})
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token != "custom-token-value" {
		t.Fatalf("expected custom-token-value, got %q", token)
	}
	if counter.Load() != 1 {
		t.Fatalf("expected KeyGenerator called once, got %d", counter.Load())
	}
}

func TestCustomKeyGeneratorNotCalledWhenCookieExists(t *testing.T) {
	var counter atomic.Int32
	mw := New(Config{
		KeyGenerator: func() string {
			counter.Add(1)
			return "custom-token"
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("_csrf", "existing-token"),
	)
	testutil.AssertNoError(t, err)
	if counter.Load() != 0 {
		t.Fatalf("KeyGenerator should not be called when cookie exists, got %d calls", counter.Load())
	}
}

// --- CookieSessionOnly tests ---

func TestCookieSessionOnlyOmitsMaxAge(t *testing.T) {
	mw := New(Config{CookieSessionOnly: true})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	for _, h := range rec.Headers {
		if h[0] == "set-cookie" {
			if containsSubstring(h[1], "Max-Age") {
				t.Fatalf("expected no Max-Age in session-only cookie, got: %s", h[1])
			}
			return
		}
	}
	t.Fatal("expected set-cookie header")
}

func TestCookieSessionOnlyFalseIncludesMaxAge(t *testing.T) {
	mw := New(Config{CookieSessionOnly: false})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)

	for _, h := range rec.Headers {
		if h[0] == "set-cookie" {
			if !containsSubstring(h[1], "Max-Age=") {
				t.Fatalf("expected Max-Age in cookie, got: %s", h[1])
			}
			return
		}
	}
	t.Fatal("expected set-cookie header")
}

// --- Configurable ContextKey tests ---

func TestCustomContextKey(t *testing.T) {
	mw := New(Config{ContextKey: "my_token"})
	var token string
	handler := func(c *celeris.Context) error {
		v, ok := c.Get("my_token")
		if ok {
			token, _ = v.(string)
		}
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token == "" {
		t.Fatal("expected token stored under custom context key")
	}
}

func TestDefaultContextKey(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		v, ok := c.Get("csrf_token")
		if ok {
			token, _ = v.(string)
		}
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	if token == "" {
		t.Fatal("expected token stored under default context key")
	}
}

// --- DeleteToken tests ---

func TestDeleteTokenWithStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	store.Set(token, token, time.Hour)
	mw := New(Config{Storage: store})
	handler := func(c *celeris.Context) error {
		err := DeleteToken(c)
		if err != nil {
			return err
		}
		return c.String(200, "deleted")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Token should be removed from storage.
	_, ok := store.Get(token)
	if ok {
		t.Fatal("expected token to be deleted from storage")
	}

	// Cookie should be expired (empty value, Max-Age=0).
	for _, h := range rec.Headers {
		if h[0] == "set-cookie" && containsSubstring(h[1], "_csrf=;") {
			return
		}
	}
	t.Fatal("expected expiry set-cookie with empty value")
}

func TestDeleteTokenWithoutStorage(t *testing.T) {
	mw := New()
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	handler := func(c *celeris.Context) error {
		err := DeleteToken(c)
		if err != nil {
			return err
		}
		return c.String(200, "deleted")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Cookie should be expired (empty value, Max-Age=0).
	for _, h := range rec.Headers {
		if h[0] == "set-cookie" && containsSubstring(h[1], "_csrf=;") {
			return
		}
	}
	t.Fatal("expected expiry set-cookie with empty value")
}

func TestDeleteTokenNoCookieReturnsError(t *testing.T) {
	mw := New()
	handler := func(c *celeris.Context) error {
		return DeleteToken(c)
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 404)
}

func TestDeleteTokenNoMiddlewareReturnsError(t *testing.T) {
	handler := func(c *celeris.Context) error {
		return DeleteToken(c)
	}
	chain := []celeris.HandlerFunc{handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 404)
}

// --- HandlerFromContext tests ---

func TestHandlerFromContextReturnsHandler(t *testing.T) {
	mw := New()
	var h *Handler
	handler := func(c *celeris.Context) error {
		h = HandlerFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	if h == nil {
		t.Fatal("expected Handler from context")
	}
}

func TestHandlerFromContextNilWithoutMiddleware(t *testing.T) {
	handler := func(c *celeris.Context) error {
		h := HandlerFromContext(c)
		if h != nil {
			t.Fatal("expected nil Handler without middleware")
		}
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
}

func TestHandlerDeleteToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	store.Set(token, token, time.Hour)
	mw := New(Config{Storage: store})
	handler := func(c *celeris.Context) error {
		h := HandlerFromContext(c)
		if h == nil {
			t.Fatal("expected handler")
		}
		return h.DeleteToken(c)
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("_csrf", token),
	)
	testutil.AssertNoError(t, err)

	_, ok := store.Get(token)
	if ok {
		t.Fatal("expected token deleted")
	}
}

// --- MemoryStorage tests ---

func TestMemoryStorageGetSetDelete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 2, CleanupContext: ctx})

	// Get non-existent.
	_, ok := store.Get("key1")
	if ok {
		t.Fatal("expected not found")
	}

	// Set and Get.
	store.Set("key1", "token1", time.Hour)
	val, ok := store.Get("key1")
	if !ok || val != "token1" {
		t.Fatalf("expected token1, got %q (ok=%v)", val, ok)
	}

	// Delete and Get.
	store.Delete("key1")
	_, ok = store.Get("key1")
	if ok {
		t.Fatal("expected not found after delete")
	}
}

func TestMemoryStorageExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 1, CleanupContext: ctx})
	store.Set("key1", "token1", time.Nanosecond)
	time.Sleep(time.Millisecond)
	_, ok := store.Get("key1")
	if ok {
		t.Fatal("expected expired token not found")
	}
}

func TestMemoryStorageConcurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{Shards: 4, CleanupContext: ctx})
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "key" + string(rune('a'+n%26))
			store.Set(key, "tok", time.Hour)
			store.Get(key)
			store.Delete(key)
		}(i)
	}
	wg.Wait()
}

func TestMemoryStorageDefaultShards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemoryStorage(MemoryStorageConfig{CleanupContext: ctx})
	store.Set("k", "v", time.Hour)
	val, ok := store.Get("k")
	if !ok || val != "v" {
		t.Fatal("expected value with default shard count")
	}
}

// --- validate() tests ---

func TestValidateTokenLookupComma(t *testing.T) {
	// Valid comma-separated lookup should not panic.
	_ = New(Config{TokenLookup: "header:X-CSRF-Token,form:_csrf"})
}

func TestValidateTokenLookupInvalidSegment(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid segment in comma-separated lookup")
		}
	}()
	New(Config{TokenLookup: "header:X-CSRF-Token,invalid"})
}

func TestValidateTokenLookupInvalidSourceInComma(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid source in comma-separated lookup")
		}
	}()
	New(Config{TokenLookup: "header:X-CSRF-Token,cookie:val"})
}

// --- applyDefaults for new fields ---

func TestApplyDefaultsExpiration(t *testing.T) {
	cfg := applyDefaults(Config{})
	if cfg.Expiration != time.Hour {
		t.Fatalf("expected 1h, got %v", cfg.Expiration)
	}
	cfg = applyDefaults(Config{Expiration: 2 * time.Hour})
	if cfg.Expiration != 2*time.Hour {
		t.Fatalf("expected 2h, got %v", cfg.Expiration)
	}
}

func TestApplyDefaultsContextKey(t *testing.T) {
	cfg := applyDefaults(Config{})
	if cfg.ContextKey != "csrf_token" {
		t.Fatalf("expected csrf_token, got %q", cfg.ContextKey)
	}
	cfg = applyDefaults(Config{ContextKey: "custom"})
	if cfg.ContextKey != "custom" {
		t.Fatalf("expected custom, got %q", cfg.ContextKey)
	}
}

// --- Helpers ---

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestTokenFromContextCustomKey(t *testing.T) {
	customKey := "my_csrf_token"
	mw := New(Config{ContextKey: customKey})
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token == "" {
		t.Fatal("expected non-empty CSRF token from custom context key")
	}
}

func TestTokenFromContextDefaultKeyStillWorks(t *testing.T) {
	mw := New()
	var token string
	handler := func(c *celeris.Context) error {
		token = TokenFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if token == "" {
		t.Fatal("expected non-empty CSRF token from default context key")
	}
}

func TestTokenFromContextNoHandler(t *testing.T) {
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	token := TokenFromContext(ctx)
	if token != "" {
		t.Fatalf("expected empty token without handler, got %q", token)
	}
}

func TestHandlerStoresContextKey(t *testing.T) {
	customKey := "custom_key"
	mw := New(Config{ContextKey: customKey})
	var handlerKey string
	handler := func(c *celeris.Context) error {
		h := HandlerFromContext(c)
		if h != nil {
			handlerKey = h.contextKey
		}
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertNoError(t, err)
	if handlerKey != customKey {
		t.Fatalf("handler contextKey: got %q, want %q", handlerKey, customKey)
	}
}

// --- Granular error sentinel tests ---

func TestErrSecFetchSiteOnCrossSite(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("sec-fetch-site", "cross-site"),
	)
	testutil.AssertHTTPError(t, err, 403)
	if !errors.Is(err, ErrSecFetchSite) {
		t.Fatalf("expected ErrSecFetchSite, got %v", err)
	}
}

func TestErrOriginMismatchOnBadOrigin(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://evil.com"),
	)
	testutil.AssertHTTPError(t, err, 403)
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("expected ErrOriginMismatch, got %v", err)
	}
}

func TestErrRefererMissingOnHTTPSNoReferer(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("x-forwarded-proto", "https"),
	)
	testutil.AssertHTTPError(t, err, 403)
	if !errors.Is(err, ErrRefererMissing) {
		t.Fatalf("expected ErrRefererMissing, got %v", err)
	}
}

func TestErrRefererMismatchOnHTTPSBadReferer(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	mw := New()
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("x-forwarded-proto", "https"),
		celeristest.WithHeader("referer", "https://evil.com/page"),
	)
	testutil.AssertHTTPError(t, err, 403)
	if !errors.Is(err, ErrRefererMismatch) {
		t.Fatalf("expected ErrRefererMismatch, got %v", err)
	}
}

func TestErrSecFetchSitePassedToErrorHandler(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	var receivedErr error
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("sec-fetch-site", "cross-site"),
	)
	if !errors.Is(receivedErr, ErrSecFetchSite) {
		t.Fatalf("ErrorHandler received %v, want ErrSecFetchSite", receivedErr)
	}
}

func TestErrOriginMismatchPassedToErrorHandler(t *testing.T) {
	token := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	var receivedErr error
	mw := New(Config{
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "POST", "/submit",
		celeristest.WithHeader("x-csrf-token", token),
		celeristest.WithCookie("_csrf", token),
		celeristest.WithHeader("origin", "https://evil.com"),
	)
	if !errors.Is(receivedErr, ErrOriginMismatch) {
		t.Fatalf("ErrorHandler received %v, want ErrOriginMismatch", receivedErr)
	}
}

func TestGranularErrorSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrForbidden,
		ErrMissingToken,
		ErrTokenNotFound,
		ErrOriginMismatch,
		ErrRefererMissing,
		ErrRefererMismatch,
		ErrSecFetchSite,
	}
	seen := make(map[string]bool, len(sentinels))
	for _, e := range sentinels {
		msg := e.Error()
		if seen[msg] {
			t.Fatalf("duplicate sentinel message: %q", msg)
		}
		seen[msg] = true
	}
}

// --- Wildcard origin scheme enforcement tests ---

func TestValidateWildcardHTTPPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for wildcard origin with http:// scheme")
		}
	}()
	New(Config{
		TrustedOrigins: []string{"http://*.example.com"},
	})
}

func TestValidateWildcardHTTPSAllowed(t *testing.T) {
	// Should not panic: HTTPS wildcard is fine.
	_ = New(Config{
		TrustedOrigins: []string{"https://*.example.com"},
	})
}

func TestValidateExactMatchHTTPAllowed(t *testing.T) {
	// Exact match origins can use any scheme.
	_ = New(Config{
		TrustedOrigins: []string{"http://trusted.example.com"},
	})
}

func TestValidateExactMatchHTTPSAllowed(t *testing.T) {
	// Exact match origins with HTTPS.
	_ = New(Config{
		TrustedOrigins: []string{"https://trusted.example.com"},
	})
}

func TestValidateWildcardNoSchemePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for wildcard origin without https:// prefix")
		}
	}()
	New(Config{
		TrustedOrigins: []string{"*.example.com"},
	})
}

func TestValidateMixedOriginsHTTPWildcardPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when any wildcard uses http://")
		}
	}()
	New(Config{
		TrustedOrigins: []string{
			"https://trusted.example.com",
			"http://*.evil.com",
		},
	})
}

func TestValidateMixedOriginsAllValid(t *testing.T) {
	// Should not panic: exact HTTP + wildcard HTTPS.
	_ = New(Config{
		TrustedOrigins: []string{
			"http://trusted.example.com",
			"https://*.example.com",
		},
	})
}
