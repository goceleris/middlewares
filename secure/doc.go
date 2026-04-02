// Package secure provides OWASP security headers middleware for celeris.
//
// The middleware sets a comprehensive suite of HTTP security headers on
// every response. All non-empty header values are pre-computed into a flat
// slice at initialization. The hot path iterates this slice with zero
// allocations.
//
// # Default Headers
//
// The following headers are set by default:
//
//   - X-Content-Type-Options: "nosniff" -- prevents browsers from MIME-sniffing
//     the response away from the declared Content-Type, blocking drive-by
//     download attacks.
//   - X-Frame-Options: "SAMEORIGIN" -- prevents the page from being loaded in
//     an iframe on a different origin, mitigating clickjacking.
//   - X-XSS-Protection: "0" -- disables the legacy browser XSS auditor, which
//     can introduce XSS via selective response filtering (modern best practice).
//   - Strict-Transport-Security (HSTS) -- tells browsers to only connect via
//     HTTPS for the configured max-age, preventing protocol downgrade attacks.
//     HSTS is only sent over HTTPS connections (detected via c.Scheme(), which
//     checks X-Forwarded-Proto internally). Set [Config].HSTSMaxAge to -1 to
//     omit the header entirely. Set [Config].HSTSExcludeSubdomains to true to
//     remove the includeSubDomains directive.
//   - Referrer-Policy: "strict-origin-when-cross-origin" -- limits the
//     Referer header to the origin on cross-origin requests, preventing URL
//     path leakage.
//   - Cross-Origin-Opener-Policy: "same-origin" -- isolates the browsing
//     context from cross-origin popups, preventing Spectre-style side-channel
//     attacks.
//   - Cross-Origin-Resource-Policy: "same-origin" -- prevents other origins
//     from loading the resource, mitigating cross-origin data leaks.
//   - Cross-Origin-Embedder-Policy: "require-corp" -- ensures all sub-resources
//     are loaded with CORP/CORS, enabling SharedArrayBuffer and high-resolution
//     timers safely.
//   - X-DNS-Prefetch-Control: "off" -- disables DNS prefetching to prevent
//     leaking which links the user might follow.
//   - X-Permitted-Cross-Domain-Policies: "none" -- prevents Adobe Flash and
//     Acrobat from loading data from the domain.
//   - Origin-Agent-Cluster: "?1" -- requests the browser to place the origin
//     in its own agent cluster, isolating it from same-site cross-origin pages
//     for Spectre mitigation.
//   - X-Download-Options: "noopen" -- prevents IE from opening downloaded files
//     directly in the browser context, forcing a save-to-disk prompt.
//
// # Optional Headers
//
// Content-Security-Policy and Permissions-Policy are only included when
// their respective [Config] fields are non-empty. Set [Config].CSPReportOnly
// to true to use Content-Security-Policy-Report-Only instead of
// Content-Security-Policy, allowing you to test a policy without
// enforcement.
//
// # HSTS Configuration
//
// HSTS is on by default with a 2-year max-age and includeSubDomains. Use
// [Config].HSTSExcludeSubdomains to remove the includeSubDomains directive,
// [Config].HSTSPreload to add the preload flag, and [Config].HSTSMaxAge set
// to -1 to suppress the header entirely.
//
// When [Config].HSTSPreload is true, validate() enforces two HSTS preload
// requirements and panics at initialization if violated:
//   - HSTSMaxAge must be >= 31536000 (1 year).
//   - HSTSExcludeSubdomains must be false (preload requires includeSubDomains).
//
// Additionally, setting CSPReportOnly without a ContentSecurityPolicy panics,
// as report-only mode without a policy is meaningless.
//
// # Suppressing Individual Headers
//
// Set any string header field to [Suppress] ("-") to explicitly omit that
// header from the response. Unlike an empty string (which triggers the
// default value), Suppress survives applyDefaults and causes buildHeaders
// to skip the header entirely:
//
//	server.Use(secure.New(secure.Config{
//	    XFrameOptions: secure.Suppress, // omit X-Frame-Options
//	}))
//
// # Skipping
//
// Use [Config].Skip for dynamic skip logic or [Config].SkipPaths for
// exact-match path exclusions (e.g., health check endpoints). Skipped
// requests receive no security headers at all.
//
// # Usage
//
// Default configuration (all OWASP-recommended headers):
//
//	server.Use(secure.New())
//
// Custom configuration (override specific headers):
//
//	server.Use(secure.New(secure.Config{
//	    ContentSecurityPolicy: "default-src 'self'",
//	    HSTSMaxAge:            31536000,
//	    HSTSPreload:           true,
//	}))
//
// Skip health check paths:
//
//	server.Use(secure.New(secure.Config{
//	    SkipPaths: []string{"/health", "/ready"},
//	}))
//
// Suppress a header by setting its value to [Suppress] ("-"). For HSTS,
// set [Config].HSTSMaxAge to -1 to omit the header.
package secure
