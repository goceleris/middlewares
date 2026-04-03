// Package keyauth provides API key authentication middleware for celeris.
//
// The middleware extracts an API key from a configurable source (header,
// query parameter, cookie, form field, or URL parameter), validates it via
// a user-supplied function, and stores the authenticated key in the context
// store under [ContextKey] ("keyauth_key"). Failed authentication returns
// 401 with a WWW-Authenticate header.
//
// [Config].Validator is required; omitting it panics at initialization.
//
// Simple usage with static keys (constant-time comparison):
//
//	server.Use(keyauth.New(keyauth.Config{
//	    Validator: keyauth.StaticKeys("key-1", "key-2"),
//	}))
//
// Custom validator with context access:
//
//	server.Use(keyauth.New(keyauth.Config{
//	    Validator: func(c *celeris.Context, key string) (bool, error) {
//	        return checkDB(c, key)
//	    },
//	    KeyLookup: "query:api_key",
//	}))
//
// # Key Lookup Sources
//
// The KeyLookup string supports these sources:
//
//   - "header:Name" or "header:Name:Prefix" -- read from request header, optionally strip prefix.
//   - "query:name" -- read from query parameter.
//   - "cookie:name" -- read from cookie.
//   - "form:name" -- read from form field (URL-encoded or multipart).
//   - "param:name" -- read from URL path parameter (e.g. :token).
//
// Multiple sources can be comma-separated for fallback:
//
//	KeyLookup: "header:Authorization:Bearer ,query:api_key,form:api_key"
//
// # Retrieving the Key
//
// Use [KeyFromContext] to retrieve the authenticated key from downstream
// handlers:
//
//	key := keyauth.KeyFromContext(c) // reads ContextKey from context store
//
// # Success Handler
//
// [Config].SuccessHandler is called after a key passes validation, before
// c.Next(). Use it to enrich the request context:
//
//	server.Use(keyauth.New(keyauth.Config{
//	    Validator: keyauth.StaticKeys("admin-key"),
//	    SuccessHandler: func(c *celeris.Context) {
//	        c.Set("role", "admin")
//	    },
//	}))
//
// # WWW-Authenticate Header
//
// On 401 responses, the middleware sets a WWW-Authenticate header using
// [Config].AuthScheme and [Config].Realm:
//
//   - AuthScheme defaults to "" (uses "ApiKey" in the header).
//   - Realm defaults to "Restricted".
//   - Example: WWW-Authenticate: ApiKey realm="Restricted"
//   - With AuthScheme "Bearer": WWW-Authenticate: Bearer realm="Restricted"
//
// # Constant-Time Comparison
//
// [StaticKeys] uses length-padded constant-time comparison via
// [crypto/subtle] to prevent timing side-channels. All candidate keys
// are right-padded to the maximum key length at initialization. At
// validation time the input key is padded into a stack-allocated buffer
// for keys up to 256 bytes (zero heap allocation), then compared against
// every padded candidate. A separate constant-time length check ensures
// that padding collisions do not produce false positives.
//
// [ErrUnauthorized] and [ErrMissingKey] are the exported sentinel errors
// (both 401) returned on authentication failure, usable with errors.Is for
// error handling in upstream middleware.
//
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions. SkipPaths uses
// literal string equality against [celeris.Context.Path] -- no glob,
// regex, or prefix matching is performed.
//
// # Input Key Size
//
// This middleware does not enforce an upper bound on the extracted key
// length. In practice, upstream HTTP header parsing (typically 8 KB
// per header line) limits the key size for header-based extraction.
// Callers using query, form, or param extraction should apply their
// own size limits if needed.
package keyauth
