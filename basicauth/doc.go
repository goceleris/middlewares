// Package basicauth provides HTTP Basic Authentication middleware for
// celeris.
//
// The middleware parses the Authorization header, validates credentials
// via a user-supplied function, and stores the authenticated username
// in the context store under [UsernameKey] ("basicauth_username"). Failed
// authentication returns 401 with a WWW-Authenticate header.
//
// One of [Config].Validator, [Config].ValidatorWithContext, [Config].Users,
// or [Config].HashedUsers is required; omitting all four panics at
// initialization.
//
// Simple usage with a Users map (auto-generates a constant-time validator):
//
//	server.Use(basicauth.New(basicauth.Config{
//	    Users: map[string]string{
//	        "admin": "secret",
//	        "user":  "pass",
//	    },
//	}))
//
// Hashed passwords with SHA-256 (avoids storing plaintext):
//
//	server.Use(basicauth.New(basicauth.Config{
//	    HashedUsers: map[string]string{
//	        "admin": basicauth.HashPassword("secret"),
//	    },
//	}))
//
// WARNING: SHA-256 is a fast hash with no work factor. It is NOT suitable
// for high-security password storage where offline brute-force attacks are
// a concern. For those scenarios, use a dedicated password hashing algorithm
// such as bcrypt, scrypt, or Argon2 inside a custom [Config].Validator or
// via [Config].HashedUsersFunc.
// HashedUsers with SHA-256 is provided as a convenience for environments
// where passwords are already protected by other means (e.g., short-lived
// tokens, internal services behind a VPN, or defense-in-depth layers).
//
// Plugging in bcrypt via HashedUsersFunc (requires golang.org/x/crypto):
//
//	server.Use(basicauth.New(basicauth.Config{
//	    HashedUsers: map[string]string{
//	        "admin": "$2a$10$...", // bcrypt hash
//	    },
//	    HashedUsersFunc: func(hash, password string) bool {
//	        return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
//	    },
//	}))
//
// Custom validator with context access:
//
//	server.Use(basicauth.New(basicauth.Config{
//	    ValidatorWithContext: func(c *celeris.Context, user, pass string) bool {
//	        return checkDB(c, user, pass)
//	    },
//	    Realm: "API",
//	}))
//
// # Retrieving the Username
//
// Use [UsernameFromContext] to retrieve the authenticated username from
// downstream handlers:
//
//	name := basicauth.UsernameFromContext(c) // reads UsernameKey from context store
//
// # Header Size Limit
//
// [Config].HeaderLimit (default 4096) caps the Authorization header
// size in bytes. Requests exceeding this limit receive a 431 (Request
// Header Fields Too Large) response via the ErrorHandler, preventing
// oversized credentials from reaching the base64 decoder or validator.
// [ErrHeaderTooLarge] is the exported sentinel error for this case.
//
// # Sentinel Errors: 400 vs 401
//
// [ErrUnauthorized] (401) is returned when credentials are absent, use
// the wrong scheme (e.g. Bearer instead of Basic), or fail validation.
//
// [ErrBadRequest] (400) is returned when the Authorization header is
// syntactically malformed: invalid base64 encoding, missing colon
// separator in the decoded payload, or credentials containing invalid
// UTF-8 sequences or ASCII control characters. The [Config].ErrorHandler
// receives the appropriate sentinel so users can distinguish malformed
// requests from authentication failures.
//
// Note: [ErrUnauthorized], [ErrBadRequest], and [ErrHeaderTooLarge] are
// exported package-level variables (not constants) because [celeris.HTTPError]
// is a struct. Callers should compare with == for identity checks in
// ErrorHandler callbacks but must not reassign these variables.
//
// # Cache-Control and Vary Headers
//
// The default error handler sets Cache-Control: no-store and
// Vary: Authorization on both 401 and 400 responses. This prevents
// browsers and intermediary caches from caching failed authentication
// responses. Custom error handlers should replicate this behavior when
// appropriate.
//
// # Credential Validation
//
// After base64 decoding, the middleware rejects credentials that contain
// invalid UTF-8 sequences or ASCII control characters (bytes < 0x20 or
// 0x7F DEL). This prevents injection of binary data or terminal escape
// sequences through authentication headers. Such requests receive a 400
// via [ErrBadRequest] rather than a 401.
//
// NFC normalization is intentionally omitted to avoid a dependency on
// golang.org/x/text. Applications that accept Unicode passwords should
// normalize to NFC before hashing if equivalence matters.
//
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
package basicauth
