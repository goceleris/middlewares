package keyauth

import (
	"crypto/subtle"
	"errors"
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func validatorFor(expected string) func(*celeris.Context, string) (bool, error) {
	want := []byte(expected)
	return func(_ *celeris.Context, key string) (bool, error) {
		return subtle.ConstantTimeCompare([]byte(key), want) == 1, nil
	}
}

func TestHeaderExtractionDefault(t *testing.T) {
	mw := New(Config{Validator: validatorFor("test-key")})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "test-key"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
	if storedKey != "test-key" {
		t.Fatalf("key in context: got %q, want %q", storedKey, "test-key")
	}
}

func TestQueryExtraction(t *testing.T) {
	mw := New(Config{
		KeyLookup: "query:api_key",
		Validator: validatorFor("qkey"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithQuery("api_key", "qkey"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "qkey" {
		t.Fatalf("key in context: got %q, want %q", storedKey, "qkey")
	}
}

func TestCookieExtraction(t *testing.T) {
	mw := New(Config{
		KeyLookup: "cookie:auth_token",
		Validator: validatorFor("ckey"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithCookie("auth_token", "ckey"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "ckey" {
		t.Fatalf("key in context: got %q, want %q", storedKey, "ckey")
	}
}

func TestMissingKeyReturnsErrMissingKey(t *testing.T) {
	mw := New(Config{Validator: validatorFor("test-key")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 401)
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("expected ErrMissingKey, got %v", err)
	}
}

func TestInvalidKeyReturnsErrUnauthorized(t *testing.T) {
	mw := New(Config{Validator: validatorFor("correct-key")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "wrong-key"),
	)
	testutil.AssertHTTPError(t, err, 401)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestStaticKeysSingleValid(t *testing.T) {
	mw := New(Config{Validator: StaticKeys("key-alpha")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "key-alpha"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestStaticKeysMultipleValid(t *testing.T) {
	mw := New(Config{Validator: StaticKeys("key-1", "key-2", "key-3")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	for _, key := range []string{"key-1", "key-2", "key-3"} {
		rec, err := testutil.RunChain(t, chain, "GET", "/",
			celeristest.WithHeader("x-api-key", key),
		)
		testutil.AssertNoError(t, err)
		testutil.AssertStatus(t, rec, 200)
	}
}

func TestStaticKeysInvalid(t *testing.T) {
	mw := New(Config{Validator: StaticKeys("key-1", "key-2")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "key-wrong"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestStaticKeysDifferentLengths(t *testing.T) {
	// Keys of different lengths must all be compared timing-safely.
	mw := New(Config{Validator: StaticKeys("short", "medium-key", "a-very-long-api-key")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	for _, key := range []string{"short", "medium-key", "a-very-long-api-key"} {
		rec, err := testutil.RunChain(t, chain, "GET", "/",
			celeristest.WithHeader("x-api-key", key),
		)
		testutil.AssertNoError(t, err)
		testutil.AssertStatus(t, rec, 200)
	}

	// Wrong key (same length as one valid key) should fail.
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "xxxxx"),
	)
	testutil.AssertHTTPError(t, err, 401)

	// Wrong key (different length from all) should fail.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "ab"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestBearerPrefixStripping(t *testing.T) {
	mw := New(Config{
		KeyLookup: "header:Authorization:Bearer ",
		Validator: validatorFor("my-token"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Bearer my-token"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "my-token" {
		t.Fatalf("key in context: got %q, want %q", storedKey, "my-token")
	}
}

func TestBearerPrefixMissing(t *testing.T) {
	mw := New(Config{
		KeyLookup: "header:Authorization:Bearer ",
		Validator: validatorFor("my-token"),
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Without the Bearer prefix, key extraction returns empty.
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "my-token"),
	)
	testutil.AssertHTTPError(t, err, 401)
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("expected ErrMissingKey, got %v", err)
	}
}

func TestMultiSourceExtraction(t *testing.T) {
	mw := New(Config{
		KeyLookup: "header:Authorization:Bearer ,query:api_key",
		Validator: validatorFor("my-token"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// First source (header) should work.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Bearer my-token"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "my-token" {
		t.Fatalf("key from header: got %q, want %q", storedKey, "my-token")
	}

	// Second source (query) fallback should work.
	storedKey = ""
	rec, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithQuery("api_key", "my-token"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "my-token" {
		t.Fatalf("key from query: got %q, want %q", storedKey, "my-token")
	}

	// No source provides a key.
	_, err = testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 401)
}

func TestCustomErrorHandler(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("correct"),
		ErrorHandler: func(_ *celeris.Context, _ error) error {
			return celeris.NewHTTPError(403, "Forbidden")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "wrong"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestCustomErrorHandlerOnMissingKey(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("correct"),
		ErrorHandler: func(_ *celeris.Context, _ error) error {
			return celeris.NewHTTPError(400, "Key required")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 400)
}

func TestSkipBypassesAuth(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("test-key"),
		Skip:      func(_ *celeris.Context) bool { return true },
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

func TestSkipPathsBypassesAuth(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("test-key"),
		SkipPaths: []string{"/health", "/ready"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	rec, err := testutil.RunChain(t, chain, "GET", "/health")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	rec, err = testutil.RunChain(t, chain, "GET", "/ready")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	_, err = testutil.RunChain(t, chain, "GET", "/protected")
	testutil.AssertHTTPError(t, err, 401)
}

func TestKeyFromContextNoAuth(t *testing.T) {
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	if got := KeyFromContext(ctx); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestKeyFromContextWithAuth(t *testing.T) {
	mw := New(Config{Validator: validatorFor("my-key")})
	var key string
	handler := func(c *celeris.Context) error {
		key = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "my-key"),
	)
	if key != "my-key" {
		t.Fatalf("KeyFromContext: got %q, want %q", key, "my-key")
	}
}

func TestNilValidatorPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil Validator")
		}
	}()
	New(Config{Validator: nil})
}

func TestInvalidKeyLookupFormatPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid KeyLookup format")
		}
	}()
	New(Config{
		KeyLookup: "bad",
		Validator: validatorFor("x"),
	})
}

func TestUnsupportedKeyLookupSourcePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for unsupported KeyLookup source")
		}
	}()
	New(Config{
		KeyLookup: "redis:token",
		Validator: validatorFor("x"),
	})
}

func TestDefaultConfigKeyLookup(t *testing.T) {
	if DefaultConfig.KeyLookup != "header:X-API-Key" {
		t.Fatalf("default KeyLookup: got %q, want %q", DefaultConfig.KeyLookup, "header:X-API-Key")
	}
}

func TestApplyDefaultsFixesEmptyKeyLookup(t *testing.T) {
	cfg := applyDefaults(Config{KeyLookup: ""})
	if cfg.KeyLookup != "header:X-API-Key" {
		t.Fatalf("expected header:X-API-Key, got %q", cfg.KeyLookup)
	}
}

func TestContextKeyConstant(t *testing.T) {
	if ContextKey != "keyauth_key" {
		t.Fatalf("ContextKey: got %q, want %q", ContextKey, "keyauth_key")
	}
}

func TestValidatorErrorPropagated(t *testing.T) {
	dbErr := errors.New("db connection failed")
	mw := New(Config{
		Validator: func(_ *celeris.Context, _ string) (bool, error) {
			return false, dbErr
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "some-key"),
	)
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected db error, got %v", err)
	}
}

func TestSkipDoesNotStoreKey(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("test-key"),
		Skip:      func(_ *celeris.Context) bool { return true },
	})
	var key string
	handler := func(c *celeris.Context) error {
		key = KeyFromContext(c)
		return nil
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "test-key"),
	)
	if key != "" {
		t.Fatalf("expected empty key on skip, got %q", key)
	}
}

func TestStaticKeysEmpty(t *testing.T) {
	mw := New(Config{Validator: StaticKeys()})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "anything"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

// --- Form extractor tests ---

func TestFormExtraction(t *testing.T) {
	mw := New(Config{
		KeyLookup: "form:api_key",
		Validator: validatorFor("form-key"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "POST", "/",
		celeristest.WithContentType("application/x-www-form-urlencoded"),
		celeristest.WithBody([]byte("api_key=form-key")),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "form-key" {
		t.Fatalf("key from form: got %q, want %q", storedKey, "form-key")
	}
}

func TestFormExtractionMissing(t *testing.T) {
	mw := New(Config{
		KeyLookup: "form:api_key",
		Validator: validatorFor("form-key"),
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "POST", "/",
		celeristest.WithContentType("application/x-www-form-urlencoded"),
		celeristest.WithBody([]byte("other=value")),
	)
	testutil.AssertHTTPError(t, err, 401)
}

// --- Param extractor tests ---

func TestParamExtraction(t *testing.T) {
	mw := New(Config{
		KeyLookup: "param:token",
		Validator: validatorFor("param-key"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/api/param-key",
		celeristest.WithParam("token", "param-key"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "param-key" {
		t.Fatalf("key from param: got %q, want %q", storedKey, "param-key")
	}
}

func TestParamExtractionMissing(t *testing.T) {
	mw := New(Config{
		KeyLookup: "param:token",
		Validator: validatorFor("x"),
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/api/")
	testutil.AssertHTTPError(t, err, 401)
}

// --- SuccessHandler tests ---

func TestSuccessHandler(t *testing.T) {
	var called bool
	mw := New(Config{
		Validator: validatorFor("test-key"),
		SuccessHandler: func(c *celeris.Context) {
			called = true
			c.Set("tenant", "acme")
		},
	})
	var tenant string
	handler := func(c *celeris.Context) error {
		v, _ := c.Get("tenant")
		if v != nil {
			tenant = v.(string)
		}
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "test-key"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if !called {
		t.Fatal("expected SuccessHandler to be called")
	}
	if tenant != "acme" {
		t.Fatalf("tenant: got %q, want %q", tenant, "acme")
	}
}

func TestSuccessHandlerNotCalledOnFailure(t *testing.T) {
	var called bool
	mw := New(Config{
		Validator: validatorFor("correct"),
		SuccessHandler: func(_ *celeris.Context) {
			called = true
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "wrong"),
	)
	testutil.AssertHTTPError(t, err, 401)
	if called {
		t.Fatal("expected SuccessHandler NOT to be called on auth failure")
	}
}

func TestSuccessHandlerNilIsNoOp(t *testing.T) {
	mw := New(Config{
		Validator:      validatorFor("test-key"),
		SuccessHandler: nil,
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("x-api-key", "test-key"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

// --- WWW-Authenticate header tests ---

func TestWWWAuthenticateDefaultScheme(t *testing.T) {
	mw := New(Config{Validator: validatorFor("correct")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHandlers(chain...),
		celeristest.WithHeader("x-api-key", "wrong"),
	)
	err := ctx.Next()
	testutil.AssertHTTPError(t, err, 401)

	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" {
			if h[1] != `ApiKey realm="Restricted"` {
				t.Fatalf("www-authenticate: got %q, want %q", h[1], `ApiKey realm="Restricted"`)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected www-authenticate response header")
	}
}

func TestWWWAuthenticateCustomScheme(t *testing.T) {
	mw := New(Config{
		Validator:  validatorFor("correct"),
		AuthScheme: "Bearer",
		Realm:      "MyApp",
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHandlers(chain...),
	)
	err := ctx.Next()
	testutil.AssertHTTPError(t, err, 401)

	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" {
			expected := `Bearer realm="MyApp"`
			if h[1] != expected {
				t.Fatalf("www-authenticate: got %q, want %q", h[1], expected)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected www-authenticate response header")
	}
}

func TestWWWAuthenticateOnMissingKey(t *testing.T) {
	mw := New(Config{Validator: validatorFor("correct")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHandlers(chain...),
	)
	err := ctx.Next()
	testutil.AssertHTTPError(t, err, 401)

	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected www-authenticate header on missing key")
	}
}

func TestWWWAuthenticateNotSetOnSuccess(t *testing.T) {
	mw := New(Config{Validator: validatorFor("test-key")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHandlers(chain...),
		celeristest.WithHeader("x-api-key", "test-key"),
	)
	err := ctx.Next()
	testutil.AssertNoError(t, err)

	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" {
			t.Fatal("expected no www-authenticate header on successful auth")
		}
	}
}

func TestDefaultRealm(t *testing.T) {
	cfg := applyDefaults(Config{Validator: validatorFor("x")})
	if cfg.Realm != "Restricted" {
		t.Fatalf("Realm: got %q, want %q", cfg.Realm, "Restricted")
	}
}

func TestCustomRealm(t *testing.T) {
	cfg := applyDefaults(Config{Validator: validatorFor("x"), Realm: "Admin"})
	if cfg.Realm != "Admin" {
		t.Fatalf("Realm: got %q, want %q", cfg.Realm, "Admin")
	}
}

func TestWWWAuthenticateValue(t *testing.T) {
	tests := []struct {
		scheme string
		realm  string
		want   string
	}{
		{"", "Restricted", `ApiKey realm="Restricted"`},
		{"Bearer", "MyApp", `Bearer realm="MyApp"`},
		{"Token", "API", `Token realm="API"`},
	}
	for _, tt := range tests {
		got := wwwAuthenticateValue(tt.scheme, tt.realm)
		if got != tt.want {
			t.Errorf("wwwAuthenticateValue(%q, %q) = %q, want %q", tt.scheme, tt.realm, got, tt.want)
		}
	}
}

func TestMultiSourceWithFormFallback(t *testing.T) {
	mw := New(Config{
		KeyLookup: "header:X-API-Key,form:api_key",
		Validator: validatorFor("fallback-key"),
	})
	var storedKey string
	handler := func(c *celeris.Context) error {
		storedKey = KeyFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Form fallback.
	rec, err := testutil.RunChain(t, chain, "POST", "/",
		celeristest.WithContentType("application/x-www-form-urlencoded"),
		celeristest.WithBody([]byte("api_key=fallback-key")),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedKey != "fallback-key" {
		t.Fatalf("key from form fallback: got %q, want %q", storedKey, "fallback-key")
	}
}

func FuzzKeyAuthHeader(f *testing.F) {
	f.Add("valid-key")
	f.Add("")
	f.Add("a")
	f.Add("very-long-key-" + string(make([]byte, 1024)))
	f.Fuzz(func(t *testing.T, key string) {
		mw := New(Config{
			Validator: func(_ *celeris.Context, k string) (bool, error) {
				return k == "valid-key", nil
			},
		})
		handler := func(c *celeris.Context) error {
			return c.String(200, "ok")
		}
		chain := []celeris.HandlerFunc{mw, handler}
		opts := []celeristest.Option{}
		if key != "" {
			opts = append(opts, celeristest.WithHeader("x-api-key", key))
		}
		_, _ = testutil.RunChain(t, chain, "GET", "/fuzz", opts...)
	})
}
