// Package basicauth provides HTTP Basic Authentication middleware for
// celeris.
//
// The middleware parses the Authorization header, validates credentials
// via a user-supplied function, and stores the authenticated username
// in the context store under [UsernameKey] ("basicauth_username"). Failed
// authentication returns 401 with a WWW-Authenticate header.
//
// One of [Config].Validator, [Config].ValidatorWithContext, or
// [Config].Users is required; omitting all three panics at initialization.
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
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
//
package basicauth
