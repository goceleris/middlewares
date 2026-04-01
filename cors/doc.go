// Package cors provides Cross-Origin Resource Sharing (CORS) middleware
// for celeris.
//
// The middleware handles preflight OPTIONS requests and sets the
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
// Using AllowCredentials with a wildcard origin ("*") panics at
// initialization, as this combination is forbidden by the CORS spec.
package cors
