package basicauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func validatorFor(user, pass string) func(string, string) bool {
	return func(u, p string) bool {
		return subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1
	}
}

func TestValidCredentialsPass(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	var storedUser string
	handler := func(c *celeris.Context) error {
		storedUser = UsernameFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
	if storedUser != "admin" {
		t.Fatalf("user in context: got %q, want %q", storedUser, "admin")
	}
}

func TestInvalidCredentialsReturn401(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestMissingAuthHeaderReturn401(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 401)
}

func TestWWWAuthenticateHeaderSet(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 401)
	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" && h[1] == `Basic realm="Restricted"` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected www-authenticate header with realm Restricted, got %v", ctx.ResponseHeaders())
	}
}

func TestCustomRealm(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		Realm:     "MyApp",
	})
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 401)
	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" && h[1] == `Basic realm="MyApp"` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected www-authenticate header with realm MyApp, got %v", ctx.ResponseHeaders())
	}
}

func TestCustomErrorHandler(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(_ *celeris.Context, _ error) error {
			return celeris.NewHTTPError(403, "Forbidden")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"),
	)
	testutil.AssertHTTPError(t, err, 403)
}

func TestSkipBypassesAuth(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
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

func TestNilValidatorPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil Validator")
		}
	}()
	New(Config{Validator: nil})
}

func TestMalformedAuthHeader(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "NotBasic abc123"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestBadBase64AuthHeader(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic !!!notbase64!!!"),
	)
	testutil.AssertHTTPError(t, err, 400)
}

func TestEmptyUsernamePassword(t *testing.T) {
	mw := New(Config{
		Validator: func(u, p string) bool { return u == "" && p == "" },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("", ""),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestWrongUserRightPassword(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("wrong", "secret"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestDefaultConfigNoArgs(t *testing.T) {
	if DefaultConfig.Realm != "Restricted" {
		t.Fatalf("default Realm: got %q, want %q", DefaultConfig.Realm, "Restricted")
	}
}

func TestApplyDefaultsFixesEmptyRealm(t *testing.T) {
	cfg := applyDefaults(Config{Realm: ""})
	if cfg.Realm != "Restricted" {
		t.Fatalf("expected Restricted, got %q", cfg.Realm)
	}
}

func TestUsersMapValid(t *testing.T) {
	mw := New(Config{Users: map[string]string{"admin": "secret", "user": "pass"}})
	var storedUser string
	handler := func(c *celeris.Context) error {
		storedUser = UsernameFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedUser != "admin" {
		t.Fatalf("UsernameFromContext: got %q, want %q", storedUser, "admin")
	}
}

func TestUsersMapInvalid(t *testing.T) {
	mw := New(Config{Users: map[string]string{"admin": "secret"}})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestUsersMapUnknownUser(t *testing.T) {
	mw := New(Config{Users: map[string]string{"admin": "secret"}})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("unknown", "secret"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestUsersMapSecondUser(t *testing.T) {
	mw := New(Config{Users: map[string]string{"admin": "secret", "user2": "pass2"}})
	var storedUser string
	handler := func(c *celeris.Context) error {
		storedUser = UsernameFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("user2", "pass2"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedUser != "user2" {
		t.Fatalf("UsernameFromContext: got %q, want %q", storedUser, "user2")
	}
}

func TestNilValidatorAndNilUsersPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when both Validator and Users are nil")
		}
	}()
	New(Config{})
}

func TestValidatorTakesPrecedenceOverUsers(t *testing.T) {
	called := false
	mw := New(Config{
		Validator: func(u, p string) bool {
			called = true
			return u == "custom" && p == "val"
		},
		Users: map[string]string{"admin": "secret"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("custom", "val"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if !called {
		t.Fatal("expected custom Validator to be called")
	}
}

func TestUsernameFromContextNoAuth(t *testing.T) {
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	if got := UsernameFromContext(ctx); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestUsernameFromContextWithAuth(t *testing.T) {
	mw := New(Config{Users: map[string]string{"admin": "pass"}})
	var username string
	handler := func(c *celeris.Context) error {
		username = UsernameFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, _ = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "pass"),
	)
	if username != "admin" {
		t.Fatalf("UsernameFromContext: got %q, want %q", username, "admin")
	}
}

func TestUsernameKeyConstant(t *testing.T) {
	if UsernameKey != "basicauth_username" {
		t.Fatalf("UsernameKey: got %q, want %q", UsernameKey, "basicauth_username")
	}
}

func TestValidatorWithContext(t *testing.T) {
	mw := New(Config{
		ValidatorWithContext: func(c *celeris.Context, user, pass string) bool {
			return user == "admin" && pass == "secret" && c.Header("x-tenant") == "acme"
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// With correct tenant header.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"),
		celeristest.WithHeader("x-tenant", "acme"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Without tenant header.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestValidatorWithContextTakesPrecedence(t *testing.T) {
	called := false
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
		ValidatorWithContext: func(_ *celeris.Context, u, p string) bool {
			called = true
			return u == "ctx" && p == "pass"
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("ctx", "pass"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if !called {
		t.Fatal("expected ValidatorWithContext to be called")
	}
}

func TestValidatorWithContextAloneWorks(t *testing.T) {
	mw := New(Config{
		ValidatorWithContext: func(_ *celeris.Context, u, p string) bool {
			return u == "solo" && p == "pass"
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("solo", "pass"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestRealmQuoteEscaping(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		Realm:     `My "App"`,
	})
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 401)
	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" && h[1] == `Basic realm="My \"App\""` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected escaped realm, got %v", ctx.ResponseHeaders())
	}
}

func TestRealmBackslashEscaping(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		Realm:     `Path\to`,
	})
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 401)
	found := false
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "www-authenticate" && h[1] == `Basic realm="Path\\to"` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected escaped backslash in realm, got %v", ctx.ResponseHeaders())
	}
}

func TestUsersMapDeepCopy(t *testing.T) {
	users := map[string]string{"admin": "secret"}
	mw := New(Config{Users: users})

	// Mutate the original map after New() — should not affect the validator.
	users["admin"] = "changed"
	users["hacker"] = "injected"

	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Original password should still work.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"),
	)
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Changed password should not work.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "changed"),
	)
	testutil.AssertHTTPError(t, err, 401)

	// Injected user should not work.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("hacker", "injected"),
	)
	testutil.AssertHTTPError(t, err, 401)
}

func TestErrorHandlerReceivesError(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(c *celeris.Context, err error) error {
			receivedErr = err
			c.SetHeader("www-authenticate", `Basic realm="Test"`)
			return celeris.NewHTTPError(401, "custom")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"),
	)
	testutil.AssertHTTPError(t, err, 401)
	if receivedErr == nil {
		t.Fatal("ErrorHandler did not receive error parameter")
	}
	if receivedErr != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", receivedErr)
	}
}

func FuzzBasicAuthHeader(f *testing.F) {
	f.Add("Basic YWRtaW46c2VjcmV0") // admin:secret
	f.Add("Basic !!!")
	f.Add("Bearer token")
	f.Add("")
	f.Add("Basic ")
	f.Add("basic YWRtaW46c2VjcmV0")
	f.Fuzz(func(t *testing.T, header string) {
		mw := New(Config{
			Validator: func(u, p string) bool { return u == "admin" && p == "secret" },
		})
		handler := func(c *celeris.Context) error {
			return c.String(200, "ok")
		}
		chain := []celeris.HandlerFunc{mw, handler}
		opts := []celeristest.Option{}
		if header != "" {
			opts = append(opts, celeristest.WithHeader("authorization", header))
		}
		// Must not panic regardless of header value.
		_, _ = testutil.RunChain(t, chain, "GET", "/fuzz", opts...)
	})
}

// --- HeaderLimit tests ---

func TestHeaderLimitRejects431(t *testing.T) {
	mw := New(Config{
		Validator:   validatorFor("admin", "secret"),
		HeaderLimit: 50,
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// Create a header value that exceeds 50 bytes.
	longHeader := "Basic " + strings.Repeat("A", 50)
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", longHeader))
	testutil.AssertHTTPError(t, err, 431)
}

func TestHeaderLimitDefaultAllowsNormal(t *testing.T) {
	// Default limit is 4096 -- normal Basic auth header is well under that.
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestHeaderLimitExactlyAtLimit(t *testing.T) {
	// Header exactly at limit should pass through to normal auth flow.
	mw := New(Config{
		Validator:   validatorFor("admin", "secret"),
		HeaderLimit: 100,
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// Create a header value exactly 100 bytes long.
	hdr := strings.Repeat("A", 100)
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", hdr))
	// Should not get 431 -- should get 401 (invalid base64).
	testutil.AssertHTTPError(t, err, 401)
}

func TestHeaderLimitOneOverLimit(t *testing.T) {
	mw := New(Config{
		Validator:   validatorFor("admin", "secret"),
		HeaderLimit: 100,
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	hdr := strings.Repeat("A", 101)
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", hdr))
	testutil.AssertHTTPError(t, err, 431)
}

func TestHeaderLimitCustomErrorHandler(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator:   validatorFor("admin", "secret"),
		HeaderLimit: 30,
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return celeris.NewHTTPError(413, "too big")
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	longHeader := "Basic " + strings.Repeat("A", 30)
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", longHeader))
	testutil.AssertHTTPError(t, err, 413)
	if receivedErr != ErrHeaderTooLarge {
		t.Fatalf("expected ErrHeaderTooLarge, got %v", receivedErr)
	}
}

func TestHeaderLimitSkippedWhenNoHeader(t *testing.T) {
	mw := New(Config{
		Validator:   validatorFor("admin", "secret"),
		HeaderLimit: 10,
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// No authorization header -- should get 401, not 431.
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 401)
}

// --- UTF-8 and control character validation tests ---

func TestInvalidUTF8InUsernameRejects(t *testing.T) {
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// \xff\xfe:password — invalid UTF-8 in username
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic //46cGFzc3dvcmQ="))
	testutil.AssertHTTPError(t, err, 400)
}

func TestInvalidUTF8InPasswordRejects(t *testing.T) {
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// admin:\xff\xfe — invalid UTF-8 in password
	// base64("admin:\xff\xfe") = "YWRtaW46//4="
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic YWRtaW46//4="))
	testutil.AssertHTTPError(t, err, 400)
}

func TestControlCharTabInUsernameRejects(t *testing.T) {
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// admin\t:password — tab (0x09) in username
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic YWRtaW4JOnBhc3N3b3Jk"))
	testutil.AssertHTTPError(t, err, 400)
}

func TestControlCharNullInPasswordRejects(t *testing.T) {
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// admin:pass\x00word — null byte (0x00) in password
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic YWRtaW46cGFzcwB3b3Jk"))
	testutil.AssertHTTPError(t, err, 400)
}

func TestControlCharDELInPasswordRejects(t *testing.T) {
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// admin:pass\x7fword — DEL (0x7F) in password
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic YWRtaW46cGFzc393b3Jk"))
	testutil.AssertHTTPError(t, err, 400)
}

func TestValidUTF8CredentialsPass(t *testing.T) {
	mw := New(Config{
		Validator: func(u, p string) bool {
			return u == "admin" && p == "p\u00e4ss"
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// admin:päss — valid UTF-8 with non-ASCII
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic YWRtaW46cMOkc3M="))
	testutil.AssertNoError(t, err)
}

func TestValidCredentialBytesUnit(t *testing.T) {
	tests := []struct {
		name string
		user string
		pass string
		want bool
	}{
		{"valid ascii", "admin", "secret", true},
		{"valid utf8", "admin", "p\u00e4ss", true},
		{"space in pass", "admin", "my pass", true},
		{"invalid utf8 user", string([]byte{0xff, 0xfe}), "pass", false},
		{"invalid utf8 pass", "admin", string([]byte{0xff}), false},
		{"tab in user", "ad\tmin", "pass", false},
		{"null in pass", "admin", "pa\x00ss", false},
		{"del in user", "admin\x7f", "pass", false},
		{"newline in pass", "admin", "pass\n", false},
		{"carriage return", "admin", "pass\r", false},
		{"escape char", "admin", "\x1bpass", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validCredentialBytes(tt.user, tt.pass)
			if got != tt.want {
				t.Fatalf("validCredentialBytes(%q, %q) = %v, want %v",
					tt.user, tt.pass, got, tt.want)
			}
		})
	}
}

// --- HashedUsers (SHA-256) tests ---

func TestHashPasswordDeterministic(t *testing.T) {
	h1 := HashPassword("secret")
	h2 := HashPassword("secret")
	if h1 != h2 {
		t.Fatalf("HashPassword not deterministic: %q != %q", h1, h2)
	}
	// Verify it's a valid 64-char hex string (SHA-256 = 32 bytes = 64 hex chars).
	if len(h1) != 64 {
		t.Fatalf("HashPassword length: got %d, want 64", len(h1))
	}
	if _, err := hex.DecodeString(h1); err != nil {
		t.Fatalf("HashPassword not valid hex: %v", err)
	}
}

func TestHashPasswordMatchesSHA256(t *testing.T) {
	password := "secret"
	expected := sha256.Sum256([]byte(password))
	got := HashPassword(password)
	if got != hex.EncodeToString(expected[:]) {
		t.Fatalf("HashPassword mismatch: got %q, want %q",
			got, hex.EncodeToString(expected[:]))
	}
}

func TestHashedUsersValidCredentials(t *testing.T) {
	mw := New(Config{
		HashedUsers: map[string]string{
			"admin": HashPassword("secret"),
			"user":  HashPassword("pass"),
		},
	})
	var storedUser string
	handler := func(c *celeris.Context) error {
		storedUser = UsernameFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedUser != "admin" {
		t.Fatalf("stored user: got %q, want %q", storedUser, "admin")
	}
}

func TestHashedUsersWrongPassword(t *testing.T) {
	mw := New(Config{
		HashedUsers: map[string]string{
			"admin": HashPassword("secret"),
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"))
	testutil.AssertHTTPError(t, err, 401)
}

func TestHashedUsersUnknownUser(t *testing.T) {
	mw := New(Config{
		HashedUsers: map[string]string{
			"admin": HashPassword("secret"),
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("unknown", "secret"))
	testutil.AssertHTTPError(t, err, 401)
}

func TestHashedUsersSecondUser(t *testing.T) {
	mw := New(Config{
		HashedUsers: map[string]string{
			"admin": HashPassword("secret"),
			"user2": HashPassword("pass2"),
		},
	})
	var storedUser string
	handler := func(c *celeris.Context) error {
		storedUser = UsernameFromContext(c)
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("user2", "pass2"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if storedUser != "user2" {
		t.Fatalf("stored user: got %q, want %q", storedUser, "user2")
	}
}

func TestHashedUsersInvalidHexPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid hex hash")
		}
	}()
	New(Config{HashedUsers: map[string]string{"admin": "not-hex"}})
}

func TestHashedUsersWrongLengthPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for wrong-length hash")
		}
	}()
	New(Config{HashedUsers: map[string]string{"admin": "abcd"}})
}

func TestHashedUsersDeepCopy(t *testing.T) {
	hashed := map[string]string{"admin": HashPassword("secret")}
	mw := New(Config{HashedUsers: hashed})

	// Mutate after New().
	hashed["admin"] = HashPassword("changed")
	hashed["hacker"] = HashPassword("injected")

	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Original password should still work.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "secret"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Changed password should not work.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "changed"))
	testutil.AssertHTTPError(t, err, 401)

	// Injected user should not work.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("hacker", "injected"))
	testutil.AssertHTTPError(t, err, 401)
}

func TestUsersMapTakesPrecedenceOverHashedUsers(t *testing.T) {
	mw := New(Config{
		Users:       map[string]string{"admin": "plain"},
		HashedUsers: map[string]string{"admin": HashPassword("hashed")},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	// Users (plaintext) should win.
	rec, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "plain"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// HashedUsers password should not work.
	_, err = testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "hashed"))
	testutil.AssertHTTPError(t, err, 401)
}

// --- SkipPaths tests ---

func TestSkipPathsMatchingPathSkipsAuth(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		SkipPaths: []string{"/health", "/ready"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/health")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestSkipPathsNonMatchingPathRequiresAuth(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		SkipPaths: []string{"/health"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/api/data")
	testutil.AssertHTTPError(t, err, 401)
}

func TestSkipPathsMultiplePaths(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		SkipPaths: []string{"/health", "/ready", "/metrics"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}

	for _, path := range []string{"/health", "/ready", "/metrics"} {
		rec, err := testutil.RunChain(t, chain, "GET", path)
		testutil.AssertNoError(t, err)
		testutil.AssertStatus(t, rec, 200)
	}

	// Non-skip path requires auth.
	_, err := testutil.RunChain(t, chain, "GET", "/secret")
	testutil.AssertHTTPError(t, err, 401)
}

func TestSkipPathsAuthStillWorksOnNonSkipped(t *testing.T) {
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		SkipPaths: []string{"/health"},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	rec, err := testutil.RunChain(t, chain, "GET", "/api",
		celeristest.WithBasicAuth("admin", "secret"))
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

// --- Cache-Control + Vary header tests ---

func TestCacheControlAndVaryOn401(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	ctx, _ := celeristest.NewContextT(t, "GET", "/")
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 401)
	assertResponseHeader(t, ctx, "cache-control", "no-store")
	assertResponseHeader(t, ctx, "vary", "authorization")
}

func TestCacheControlAndVaryOn401WrongCreds(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"))
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 401)
	assertResponseHeader(t, ctx, "cache-control", "no-store")
	assertResponseHeader(t, ctx, "vary", "authorization")
}

func TestCacheControlAndVaryOn400BadBase64(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHeader("authorization", "Basic !!!bad!!!"))
	err := mw(ctx)
	testutil.AssertHTTPError(t, err, 400)
	assertResponseHeader(t, ctx, "cache-control", "no-store")
	assertResponseHeader(t, ctx, "vary", "authorization")
}

func TestNoCacheControlOnSuccess(t *testing.T) {
	mw := New(Config{Validator: validatorFor("admin", "secret")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	ctx, rec := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHandlers(chain...),
		celeristest.WithBasicAuth("admin", "secret"))
	err := ctx.Next()
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == "cache-control" {
			t.Fatal("cache-control should not be set on successful auth")
		}
	}
}

// --- ErrBadRequest (400 vs 401) tests ---

func TestErrBadRequestBadBase64(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic !!!bad!!!"))
	testutil.AssertHTTPError(t, err, 400)
	if receivedErr != ErrBadRequest {
		t.Fatalf("expected ErrBadRequest, got %v", receivedErr)
	}
}

func TestErrBadRequestNoColon(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// base64("nocolon") = "bm9jb2xvbg=="
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic bm9jb2xvbg=="))
	testutil.AssertHTTPError(t, err, 400)
	if receivedErr != ErrBadRequest {
		t.Fatalf("expected ErrBadRequest, got %v", receivedErr)
	}
}

func TestErrBadRequestControlChars(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: func(_, _ string) bool { return true },
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	// admin\t:password — tab in username
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Basic YWRtaW4JOnBhc3N3b3Jk"))
	testutil.AssertHTTPError(t, err, 400)
	if receivedErr != ErrBadRequest {
		t.Fatalf("expected ErrBadRequest, got %v", receivedErr)
	}
}

func TestErrUnauthorizedMissingHeader(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(c *celeris.Context, err error) error {
			receivedErr = err
			c.SetHeader("www-authenticate", `Basic realm="Test"`)
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/")
	testutil.AssertHTTPError(t, err, 401)
	if receivedErr != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", receivedErr)
	}
}

func TestErrUnauthorizedWrongScheme(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithHeader("authorization", "Bearer token123"))
	testutil.AssertHTTPError(t, err, 401)
	if receivedErr != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", receivedErr)
	}
}

func TestErrUnauthorizedWrongPassword(t *testing.T) {
	var receivedErr error
	mw := New(Config{
		Validator: validatorFor("admin", "secret"),
		ErrorHandler: func(_ *celeris.Context, err error) error {
			receivedErr = err
			return err
		},
	})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	_, err := testutil.RunChain(t, chain, "GET", "/",
		celeristest.WithBasicAuth("admin", "wrong"))
	testutil.AssertHTTPError(t, err, 401)
	if receivedErr != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", receivedErr)
	}
}

// --- parseBasicAuth unit tests ---

func TestParseBasicAuthOK(t *testing.T) {
	user, pass, result := parseBasicAuth("Basic YWRtaW46c2VjcmV0")
	if result != authOK {
		t.Fatalf("expected authOK, got %d", result)
	}
	if user != "admin" || pass != "secret" {
		t.Fatalf("got %q:%q, want admin:secret", user, pass)
	}
}

func TestParseBasicAuthEmptyHeader(t *testing.T) {
	_, _, result := parseBasicAuth("")
	if result != authMissing {
		t.Fatalf("expected authMissing, got %d", result)
	}
}

func TestParseBasicAuthWrongScheme(t *testing.T) {
	_, _, result := parseBasicAuth("Bearer token")
	if result != authMissing {
		t.Fatalf("expected authMissing, got %d", result)
	}
}

func TestParseBasicAuthEmptyPayload(t *testing.T) {
	_, _, result := parseBasicAuth("Basic ")
	if result != authMissing {
		t.Fatalf("expected authMissing, got %d", result)
	}
}

func TestParseBasicAuthBadBase64(t *testing.T) {
	_, _, result := parseBasicAuth("Basic !!!bad!!!")
	if result != authMalformed {
		t.Fatalf("expected authMalformed, got %d", result)
	}
}

func TestParseBasicAuthNoColon(t *testing.T) {
	// base64("nocolon") = "bm9jb2xvbg=="
	_, _, result := parseBasicAuth("Basic bm9jb2xvbg==")
	if result != authMalformed {
		t.Fatalf("expected authMalformed, got %d", result)
	}
}

func TestParseBasicAuthInvalidUTF8(t *testing.T) {
	// \xff\xfe:password
	_, _, result := parseBasicAuth("Basic //46cGFzc3dvcmQ=")
	if result != authMalformed {
		t.Fatalf("expected authMalformed, got %d", result)
	}
}

func TestParseBasicAuthControlChar(t *testing.T) {
	// admin\t:password
	_, _, result := parseBasicAuth("Basic YWRtaW4JOnBhc3N3b3Jk")
	if result != authMalformed {
		t.Fatalf("expected authMalformed, got %d", result)
	}
}

// assertResponseHeader is a test helper that checks a response header on Context.
func assertResponseHeader(t *testing.T, ctx *celeris.Context, key, want string) {
	t.Helper()
	for _, h := range ctx.ResponseHeaders() {
		if h[0] == key && h[1] == want {
			return
		}
	}
	t.Fatalf("expected response header %q=%q, got %v", key, want, ctx.ResponseHeaders())
}
