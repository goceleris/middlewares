// Deprecated: This module has been merged into github.com/goceleris/celeris/middleware.
// Import middleware packages directly from the main celeris module:
//
//	import "github.com/goceleris/celeris/middleware/cors"
//	import "github.com/goceleris/celeris/middleware/jwt"
//
// For middleware with external dependencies (metrics, otel), use:
//
//	import "github.com/goceleris/celeris/middleware/metrics"
//	import "github.com/goceleris/celeris/middleware/otel"
module github.com/goceleris/middlewares

go 1.26.0

retract [v0.0.0, v1.0.0] // All versions deprecated; use github.com/goceleris/celeris/middleware instead.

require github.com/goceleris/celeris v1.2.4

require (
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)
