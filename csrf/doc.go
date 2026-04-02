// Package csrf provides Cross-Site Request Forgery protection middleware
// for celeris using the double-submit cookie pattern, with optional
// server-side token storage for enhanced security.
//
// On safe HTTP methods (GET, HEAD, OPTIONS, TRACE by default) the
// middleware reuses an existing CSRF cookie if present, or generates a
// new cryptographically random token. The token is set as a cookie and
// stored in the context under [ContextKey] ("csrf_token") or
// [Config].ContextKey. Templates and client code can read it from the
// context or cookie to include in subsequent requests.
//
// On unsafe methods (POST, PUT, DELETE, PATCH, etc.) the middleware
// performs defense-in-depth checks (Sec-Fetch-Site and Origin validation),
// then extracts the token from both the cookie and a configurable request
// source (header, form field, or query parameter), and compares them using
// [crypto/subtle.ConstantTimeCompare]. A mismatch or missing token
// returns a 403 error.
//
// Default usage (token in X-CSRF-Token header):
//
//	server.Use(csrf.New())
//
// Custom token lookup from a form field:
//
//	server.Use(csrf.New(csrf.Config{
//	    TokenLookup: "form:_csrf",
//	}))
//
// Multiple token lookup sources (tried in order):
//
//	server.Use(csrf.New(csrf.Config{
//	    TokenLookup: "header:X-CSRF-Token,form:_csrf",
//	}))
//
// Token lookup from query parameter:
//
//	server.Use(csrf.New(csrf.Config{
//	    TokenLookup: "query:csrf_token",
//	}))
//
// # Retrieving the Token
//
// Use [TokenFromContext] to retrieve the CSRF token from downstream
// handlers:
//
//	token := csrf.TokenFromContext(c)
//
// # Server-Side Token Storage
//
// By default, the middleware uses the pure double-submit cookie pattern.
// For enhanced security, configure [Config].Storage to enable server-side
// token validation (signed double-submit). When Storage is set, tokens
// are persisted in the backend and validated against the store on unsafe
// methods.
//
//	store := csrf.NewMemoryStorage()
//	server.Use(csrf.New(csrf.Config{
//	    Storage:    store,
//	    Expiration: 2 * time.Hour,
//	}))
//
// # Single-Use Tokens
//
// [Config].SingleUseToken causes each token to be consumed after a
// single successful validation. This provides stronger replay protection
// but requires Storage to be set:
//
//	server.Use(csrf.New(csrf.Config{
//	    Storage:        csrf.NewMemoryStorage(),
//	    SingleUseToken: true,
//	}))
//
// # Deleting Tokens
//
// Use [DeleteToken] or [Handler.DeleteToken] during logout to remove
// the token from server-side storage and expire the cookie:
//
//	server.POST("/logout", func(c *celeris.Context) error {
//	    csrf.DeleteToken(c)
//	    return c.String(200, "logged out")
//	})
//
// The [Handler] can also be retrieved via [HandlerFromContext]:
//
//	h := csrf.HandlerFromContext(c)
//	if h != nil {
//	    h.DeleteToken(c)
//	}
//
// # SPA Usage
//
// For single-page applications where JavaScript needs to read the CSRF
// cookie and send the token in a request header:
//
//	server.Use(csrf.New(csrf.Config{
//	    DisableCookieHTTPOnly: true, // allow JS to read the cookie
//	}))
//
// Client-side JavaScript reads the _csrf cookie and includes it in
// requests via the X-CSRF-Token header:
//
//	fetch("/api/action", {
//	    method: "POST",
//	    headers: { "X-CSRF-Token": getCookie("_csrf") },
//	})
//
// # Trusted Origins
//
// [Config].TrustedOrigins allows cross-origin requests from specific
// origins. Wildcard subdomain patterns are supported:
//
//	server.Use(csrf.New(csrf.Config{
//	    TrustedOrigins: []string{
//	        "https://app.example.com",
//	        "https://*.example.com",
//	    },
//	}))
//
// When the Origin header is present on unsafe methods, it must match
// the request Host or one of the trusted entries.
//
// # Session-Scoped Cookies
//
// [Config].CookieSessionOnly omits MaxAge so the cookie is deleted when
// the browser closes:
//
//	server.Use(csrf.New(csrf.Config{
//	    CookieSessionOnly: true,
//	}))
//
// # Custom Context Key
//
// [Config].ContextKey overrides the default context storage key:
//
//	server.Use(csrf.New(csrf.Config{
//	    ContextKey: "my_csrf_token",
//	}))
//
// # Custom Key Generator
//
// [Config].KeyGenerator provides a custom function for token generation:
//
//	server.Use(csrf.New(csrf.Config{
//	    KeyGenerator: func() string { return myCustomTokenFunc() },
//	}))
//
// # Skipping
//
// Use [Config].Skip for dynamic skip logic or [Config].SkipPaths for
// exact-match path exclusions (e.g., webhook endpoints):
//
//	server.Use(csrf.New(csrf.Config{
//	    SkipPaths: []string{"/webhooks/stripe", "/api/public"},
//	}))
//
// # Error Handling
//
// [ErrForbidden] is returned when the submitted token does not match
// the cookie token. [ErrMissingToken] is returned when either the
// cookie or the request token is absent. Both are usable with
// errors.Is for custom error handling.
//
// A custom [Config].ErrorHandler can override the default error
// behavior:
//
//	server.Use(csrf.New(csrf.Config{
//	    ErrorHandler: func(c *celeris.Context, err error) error {
//	        return c.String(403, "CSRF validation failed")
//	    },
//	}))
package csrf
