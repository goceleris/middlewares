// Package session provides server-side session management middleware for
// celeris.
//
// Sessions are identified by a cookie (default), header, or query parameter,
// and data is stored server-side in a pluggable [Store]. The default
// [MemoryStore] uses sharded maps with a background cleanup goroutine,
// suitable for single-instance deployments.
//
// Basic usage with defaults (in-memory store, 24h sessions):
//
//	server.Use(session.New())
//
// Custom cookie name and timeouts:
//
//	server.Use(session.New(session.Config{
//	    CookieName:      "myapp_sid",
//	    IdleTimeout:     15 * time.Minute,
//	    AbsoluteTimeout: 2 * time.Hour,
//	}))
//
// # Pluggable Extractors
//
// By default the session ID is read from a cookie via [CookieExtractor].
// The [Config].Extractor field accepts any function matching the
// [Extractor] signature, and three built-in constructors are provided:
//
//   - [CookieExtractor](name) -- reads the session ID from a named
//     cookie. This is the default when [Config].Extractor is nil.
//   - [HeaderExtractor](name) -- reads the session ID from a named
//     request header. Ideal for API clients that cannot store cookies.
//   - [QueryExtractor](name) -- reads the session ID from a named
//     query parameter. Useful for callback URLs or environments where
//     headers and cookies are unavailable.
//
// [ChainExtractor] tries multiple extractors in order and returns the
// first non-empty result. This is useful when session IDs may arrive via
// different transport mechanisms:
//
//	server.Use(session.New(session.Config{
//	    Extractor: session.ChainExtractor(
//	        session.CookieExtractor("celeris_session"),
//	        session.HeaderExtractor("X-Session-ID"),
//	    ),
//	}))
//
// Example using a header extractor:
//
//	server.Use(session.New(session.Config{
//	    Extractor: session.HeaderExtractor("X-Session-ID"),
//	}))
//
// Example using a query parameter extractor:
//
//	server.Use(session.New(session.Config{
//	    Extractor: session.QueryExtractor("sid"),
//	}))
//
// When a non-cookie extractor is used, the session ID is returned in a
// response header named after [Config].CookieName so API clients can
// capture and resend it.
//
// # Accessing the Session
//
// Use [FromContext] to retrieve the session from downstream handlers:
//
//	s := session.FromContext(c)
//	s.Set("user", "admin")
//	name, ok := s.Get("user")
//
// Modified sessions are automatically saved after the handler chain returns.
// Call [Session.Destroy] to invalidate a session, or [Session.Regenerate] to
// issue a new session ID (recommended after privilege changes).
//
// # Session Methods
//
//   - Get(key) (any, bool) -- retrieve a value by key.
//   - GetString(key) string -- retrieve a string value (zero value if missing or wrong type).
//   - GetInt(key) int -- retrieve an int value (zero value if missing or wrong type).
//   - GetBool(key) bool -- retrieve a bool value (zero value if missing or wrong type).
//   - GetFloat64(key) float64 -- retrieve a float64 value (zero value if missing or wrong type).
//   - Set(key, value) -- store a key-value pair; marks session as modified.
//   - Delete(key) -- remove a key; marks session as modified.
//   - Clear() -- remove all user data; marks session as modified.
//   - Keys() []string -- return all keys in sorted order.
//   - Len() int -- return the number of stored key-value pairs.
//   - ID() string -- return the session identifier.
//   - IsFresh() bool -- true if this is a newly created session (no prior cookie).
//   - Save() error -- explicitly persist data to the store mid-handler.
//   - Destroy() error -- clear data, delete from store, expire cookie.
//   - Regenerate() error -- issue a new session ID, delete old from store.
//   - Reset() error -- combined Clear + Regenerate in a single call.
//   - SetIdleTimeout(d) -- override idle timeout for this session only.
//
// # Timeout Semantics
//
// IdleTimeout controls how long a session can be idle (no requests) before
// the store entry expires. Each request that modifies the session resets
// this timer. Default: 30 minutes.
//
// AbsoluteTimeout caps the total lifetime of a session regardless of
// activity. Once exceeded, the session is destroyed and a fresh one is
// created. This prevents long-lived sessions from accumulating risk.
// Default: 24 hours. AbsoluteTimeout must be >= IdleTimeout.
// Set to -1 to disable absolute timeout enforcement entirely.
//
// [Session.SetIdleTimeout] overrides the config-level idle timeout for an
// individual session, useful for "remember me" flows.
//
// # Browser-Session Cookies
//
// Set [Config].CookieSessionOnly to true to omit the Max-Age attribute
// from the cookie. The cookie then becomes browser-session-scoped and is
// deleted when the browser closes.
//
// # Store.Get by ID
//
// The [Store] interface's Get method accepts a raw session ID string,
// allowing direct session lookup without an HTTP context. This is useful
// for administrative tools, background jobs, or WebSocket handlers that
// need to inspect session data outside of the middleware pipeline.
//
// # Error Handling
//
// [Config].ErrorHandler is called when a store operation (Get or Save) fails.
// When nil, the error is returned directly up the middleware chain. This
// allows upstream error-handling middleware to decide the response:
//
//	server.Use(session.New(session.Config{
//	    ErrorHandler: func(c *celeris.Context, err error) error {
//	        return celeris.NewHTTPError(503, "session store unavailable")
//	    },
//	}))
//
// # Session ID Validation
//
// Incoming session IDs are validated before store lookup to prevent
// injection attacks. The default KeyGenerator produces 64-character
// lowercase hex strings, so [Config].SessionIDLength defaults to 64.
// IDs that fail validation (wrong length or non-hex characters) are
// silently treated as "no session" and a fresh session is created.
//
// If you use a custom KeyGenerator that produces IDs of a different
// length, set SessionIDLength accordingly. Set SessionIDLength to -1 to
// disable length and format validation entirely.
//
// # Implementation Notes
//
// Session objects are pooled via sync.Pool and reused across requests
// to reduce GC pressure. Fields are reset at the start of each request.
//
// # Skipping
//
// Use [Config].Skip for dynamic skip logic or [Config].SkipPaths for
// exact-match path exclusions (e.g., health check endpoints).
//
// # Custom Stores
//
// Implement the [Store] interface to back sessions with Redis, a database,
// or any other storage backend. Pass the store via [Config].Store:
//
//	server.Use(session.New(session.Config{
//	    Store: myRedisStore,
//	}))
//
// All [Store] methods receive a [context.Context] propagated from the
// request. Implementations can use it for cancellation, deadlines, or
// tracing. The built-in [MemoryStore] ignores the context since in-memory
// operations are instantaneous, but network-backed stores (Redis, SQL)
// should pass it through to their client calls.
//
// # Store-level Reset
//
// [Store].Reset wipes every session from the backend in a single call.
// This is useful for administrative "log out all users" operations or
// integration-test cleanup. The [MemoryStore] implementation iterates all
// shards, locks each one, and clears the map.
//
// [ContextKey] is the key used to store the session in the request context,
// usable with c.Get/c.Set for advanced scenarios.
package session
