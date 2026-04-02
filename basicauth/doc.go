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
// [ErrUnauthorized] is the exported sentinel error (401) returned on
// authentication failure, usable with errors.Is for error handling in
// upstream middleware.
//
// # Credential Validation
//
// After base64 decoding, the middleware rejects credentials that contain
// invalid UTF-8 sequences or ASCII control characters (bytes < 0x20 or
// 0x7F DEL). This prevents injection of binary data or terminal escape
// sequences through authentication headers.
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
