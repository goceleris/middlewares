package basicauth

import (
	"crypto/subtle"
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
		v, ok := c.Get("user")
		if ok {
			storedUser = v.(string)
		}
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
		ErrorHandler: func(_ *celeris.Context) error {
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
	testutil.AssertHTTPError(t, err, 401)
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
