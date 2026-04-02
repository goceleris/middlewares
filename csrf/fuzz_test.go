package csrf

import (
	"errors"
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"
)

func FuzzTokenValidation(f *testing.F) {
	f.Add("valid-token", "valid-token")
	f.Add("", "token")
	f.Add("token", "")
	f.Add("short", "different")
	f.Add("abcdef1234567890", "abcdef1234567890")
	f.Add("abcdef1234567890", "ABCDEF1234567890")
	f.Fuzz(func(t *testing.T, cookie, header string) {
		mw := New()
		handler := func(c *celeris.Context) error {
			return c.String(200, "ok")
		}
		chain := []celeris.HandlerFunc{mw, handler}
		opts := []celeristest.Option{
			celeristest.WithHandlers(chain...),
		}
		if cookie != "" {
			opts = append(opts, celeristest.WithCookie("_csrf", cookie))
		}
		if header != "" {
			opts = append(opts, celeristest.WithHeader("x-csrf-token", header))
		}

		ctx, _ := celeristest.NewContextT(t, "POST", "/submit", opts...)
		err := ctx.Next()

		if cookie == "" || header == "" {
			// Missing token: must get 403.
			var he *celeris.HTTPError
			if !errors.As(err, &he) || he.Code != 403 {
				t.Errorf("missing token: expected 403, got %v", err)
			}
			return
		}
		if cookie == header {
			// Matching tokens: must succeed.
			if err != nil {
				t.Errorf("matching tokens %q: unexpected error %v", cookie, err)
			}
		} else {
			// Mismatched tokens: must get 403.
			var he *celeris.HTTPError
			if !errors.As(err, &he) || he.Code != 403 {
				t.Errorf("mismatched tokens: expected 403, got %v", err)
			}
		}
	})
}
