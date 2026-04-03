// Package cors provides Cross-Origin Resource Sharing (CORS) middleware
// for celeris.
//
// The middleware handles preflight OPTIONS requests (detected via
// OPTIONS method + Access-Control-Request-Method header) and sets the
// appropriate Access-Control-* response headers. Header values are
// pre-joined at initialization for zero-alloc responses on the hot path.
//
// Allow all origins (default):
//
//	server.Use(cors.New())
//
// Restrict to specific origins with credentials:
//
//	server.Use(cors.New(cors.Config{
//	    AllowOrigins:     []string{"https://example.com"},
//	    AllowCredentials: true,
//	    MaxAge:           3600,
//	}))
//
// # Dynamic Origin Validation
//
// [Config].AllowOriginsFunc validates origins with a custom function.
// [Config].AllowOriginRequestFunc provides the full request context for
// tenant-based or header-dependent origin checks. Neither may be combined
// with a wildcard ("*") AllowOrigins entry.
//
//	server.Use(cors.New(cors.Config{
//	    AllowOriginsFunc: func(origin string) bool {
//	        return strings.HasSuffix(origin, ".example.com")
//	    },
//	}))
//
// # Subdomain Wildcards
//
// Origins may contain a single wildcard for subdomain matching
// (e.g., "https://*.example.com"). Patterns with more than one wildcard
// panic at initialization. Note that wildcards match across dots, so
// "https://*.example.com" matches multi-level subdomains like
// "https://a.b.example.com" — not just single-level subdomains.
//
// # Header Mirroring
//
// When [Config].AllowHeaders is set to an empty slice, the middleware
// mirrors the value of the Access-Control-Request-Headers header from the
// preflight request back in Access-Control-Allow-Headers. This means any
// header the client requests will be reflected as allowed without
// validation. When AllowHeaders is nil (not set), the default headers
// (Origin, Content-Type, Accept, Authorization) are used.
//
// # Private Network Access
//
// Set [Config].AllowPrivateNetwork to true to enable the Private Network
// Access spec (Access-Control-Allow-Private-Network header on preflight).
//
// Using AllowCredentials with a wildcard origin ("*") panics at
// initialization, as this combination is forbidden by the CORS spec.
package cors
