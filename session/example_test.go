package session_test

import (
	"time"

	"github.com/goceleris/celeris"

	"github.com/goceleris/middlewares/session"
)

func ExampleNew() {
	// Zero-config: in-memory store, 24h sessions, Lax cookies.
	_ = session.New()
}

func ExampleNew_customCookie() {
	// Custom cookie name and timeouts.
	_ = session.New(session.Config{
		CookieName:      "myapp_sid",
		CookieSecure:    true,
		IdleTimeout:     15 * time.Minute,
		AbsoluteTimeout: 2 * time.Hour,
	})
}

func ExampleNew_headerExtractor() {
	// API clients: read session ID from a request header.
	_ = session.New(session.Config{
		Extractor: session.HeaderExtractor("X-Session-ID"),
	})
}

func ExampleNew_queryExtractor() {
	// Read session ID from a query parameter.
	_ = session.New(session.Config{
		Extractor: session.QueryExtractor("sid"),
	})
}

func ExampleNew_sessionOnlyCookie() {
	// Browser-session-scoped cookie (no Max-Age, deleted when browser closes).
	_ = session.New(session.Config{
		CookieSessionOnly: true,
	})
}

func ExampleNew_disableAbsoluteTimeout() {
	// Disable absolute timeout enforcement (sessions live until idle timeout).
	_ = session.New(session.Config{
		AbsoluteTimeout: -1,
		IdleTimeout:     30 * time.Minute,
	})
}

func ExampleFromContext() {
	handler := func(c *celeris.Context) error {
		s := session.FromContext(c)
		s.Set("user", "admin")
		name, _ := s.Get("user")
		_ = name // "admin"
		return nil
	}
	_ = handler
}

func ExampleSession_Reset() {
	handler := func(c *celeris.Context) error {
		s := session.FromContext(c)
		// Logout: clear all data and regenerate session ID in one call.
		return s.Reset()
	}
	_ = handler
}

func ExampleSession_SetIdleTimeout() {
	handler := func(c *celeris.Context) error {
		s := session.FromContext(c)
		// "Remember me" — extend this specific session's idle timeout.
		s.SetIdleTimeout(7 * 24 * time.Hour)
		s.Set("user", "admin")
		return nil
	}
	_ = handler
}

func ExampleNew_customStore() {
	// Use a custom store (e.g., Redis).
	var myStore session.Store // = redis.NewStore(...)
	_ = session.New(session.Config{
		Store: myStore,
	})
}
