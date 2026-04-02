# celeris middleware

[![CI](https://github.com/goceleris/middlewares/actions/workflows/ci.yml/badge.svg)](https://github.com/goceleris/middlewares/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/goceleris/middlewares.svg)](https://pkg.go.dev/github.com/goceleris/middlewares)
[![Go Report Card](https://goreportcard.com/badge/github.com/goceleris/middlewares)](https://goreportcard.com/report/github.com/goceleris/middlewares)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Production-ready middleware for [celeris](https://github.com/goceleris/celeris). 17 middleware packages covering logging, recovery, CORS, rate limiting, authentication, CSRF, sessions, JWT, security headers, health checks, debugging, Prometheus metrics, and OpenTelemetry. Every middleware targets **zero allocations** on the hot path. **#1 on all benchmarks** across Fiber v3, Echo v4, Chi v5, and net/http.

## Middleware

### Core (root module)

| Package | Description | Allocs | Key Features |
|---------|-------------|--------|--------------|
| [logger](./logger/) | Structured request logging via `slog` | 0 | [FastHandler](./logger/fasthandler.go) with ANSI color, body capture, request ID auto-detection |
| [recovery](./recovery/) | Panic recovery with stack capture | 0 | Broken pipe detection, nested recovery, `StackAll`, slog structured logging |
| [cors](./cors/) | Cross-Origin Resource Sharing | 0 | O(1) origin map, wildcard patterns, PNA, `AllowOriginRequestFunc` |
| [ratelimit](./ratelimit/) | Sharded token-bucket rate limiting | 1 | `ParseRate("100-M")`, `Retry-After`, NTP clock protection |
| [requestid](./requestid/) | UUID v4 request ID generation | 2 | Buffered crypto/rand, input validation, `CounterGenerator` |
| [timeout](./timeout/) | Request timeout with preemptive mode | 8 | Cooperative + preemptive dual mode, goroutine panic recovery |
| [bodylimit](./bodylimit/) | Request body size enforcement | 0 | `Limit: "1.5GB"`, Content-Length + body dual check |
| [basicauth](./basicauth/) | HTTP Basic Authentication | 2 | `Users` map, `ValidatorWithContext`, timing-safe username miss |
| [secure](./secure/) | OWASP security headers | 0 | 13 pre-computed headers (HSTS, CSP, COOP/CORP/COEP, XSS, Referrer, Permissions, Origin-Agent-Cluster, X-Download-Options) |
| [keyauth](./keyauth/) | API key authentication | 1 | `StaticKeys()` timing-safe, Bearer prefix, multi-source, `WWW-Authenticate`, `SuccessHandler` |
| [csrf](./csrf/) | CSRF protection | 4 | Double-submit + server-side `Storage`, `SingleUseToken`, Origin/Sec-Fetch-Site/Referer, wildcard `TrustedOrigins`, `DeleteToken` |
| [session](./session/) | Session management | 5 | Pluggable `Store` + `Extractor` (cookie/header/query), absolute + idle timeout, `SetIdleTimeout`, `Reset` |
| [debug](./debug/) | Debug endpoints | 0† | Status, metrics, memory, build, routes; localhost-only by default |
| [healthcheck](./healthcheck/) | Kubernetes probes | 0 | Liveness `/livez`, readiness `/readyz`, startup `/startupz` |

| [jwt](./jwt/) | JWT authentication | 8 | Custom zero-dep parser, HMAC/RSA/ECDSA/EdDSA, JWKS auto-refresh, `ClaimsFromContext[T]()` |

### Observability (separate modules)

| Package | Description | External Dep | Install |
|---------|-------------|-------------|---------|
| [metrics](./metrics/) | Prometheus metrics | `prometheus/client_golang` | `go get github.com/goceleris/middlewares/metrics` |
| [otel](./otel/) | OpenTelemetry tracing + metrics | `go.opentelemetry.io/otel` | `go get github.com/goceleris/middlewares/otel` |

†debug endpoints are not hot-path; 0 allocs on passthrough.

## Quick Start

```
go get github.com/goceleris/middlewares              # core middleware (includes JWT)
go get github.com/goceleris/middlewares/metrics       # Prometheus (separate module)
go get github.com/goceleris/middlewares/otel          # OpenTelemetry (separate module)
```

Requires **Go 1.26+** and `github.com/goceleris/celeris` v1.2.2+.

## Usage

```go
package main

import (
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/middlewares/basicauth"
	"github.com/goceleris/middlewares/bodylimit"
	"github.com/goceleris/middlewares/cors"
	"github.com/goceleris/middlewares/logger"
	"github.com/goceleris/middlewares/ratelimit"
	"github.com/goceleris/middlewares/recovery"
	"github.com/goceleris/middlewares/requestid"
	"github.com/goceleris/middlewares/timeout"
)

func main() {
	s := celeris.New(celeris.Config{Addr: ":8080"})

	// Recommended middleware ordering
	s.Use(recovery.New())                                               // 1. Catch all panics
	s.Use(requestid.New())                                              // 2. Assign request ID
	s.Use(logger.New(logger.Config{                                     // 3. Log requests
		Output: slog.New(logger.NewFastHandler(os.Stderr,
			&logger.FastHandlerOptions{Color: true})),
	}))
	s.Use(cors.New())                                                   // 4. CORS headers
	s.Use(ratelimit.New(ratelimit.Config{Rate: "100-M"}))               // 5. Rate limit
	s.Use(bodylimit.New(bodylimit.Config{Limit: "10MB"}))               // 6. Body size limit
	s.Use(timeout.New(timeout.Config{Timeout: 5 * time.Second}))        // 7. Request timeout

	// Protected routes
	admin := s.Group("/admin")
	admin.Use(basicauth.New(basicauth.Config{
		Users: map[string]string{"admin": "secret"},
	}))
	admin.GET("/dashboard", func(c *celeris.Context) error {
		return c.JSON(200, map[string]string{"user": basicauth.UsernameFromContext(c)})
	})

	s.GET("/", func(c *celeris.Context) error {
		return c.String(200, "Hello, World!")
	})
	log.Fatal(s.Start())
}
```

## Highlights

### Zero-Alloc FastHandler with Color Output

```go
log := slog.New(logger.NewFastHandler(os.Stderr, &logger.FastHandlerOptions{
	Color: true, // ANSI colors for levels, status codes, methods, and latency
}))
```

Colors status codes (2xx green, 4xx yellow, 5xx red), HTTP methods (GET blue, POST cyan, DELETE red), latency bands (<1ms green, <1s yellow, >=1s red), and log levels. Zero allocations — 40% faster than `slog.TextHandler`.

### Human-Readable Configuration

```go
bodylimit.New(bodylimit.Config{Limit: "1.5GB"})           // fractional sizes
ratelimit.New(ratelimit.Config{Rate: "1000-H"})            // 1000 per hour
```

### Exported Error Sentinels

```go
if errors.Is(err, ratelimit.ErrTooManyRequests)    { /* 429 */ }
if errors.Is(err, basicauth.ErrUnauthorized)       { /* 401 */ }
if errors.Is(err, basicauth.ErrHeaderTooLarge)    { /* 431 */ }
if errors.Is(err, keyauth.ErrUnauthorized)         { /* 401 */ }
if errors.Is(err, keyauth.ErrMissingKey)           { /* 401 */ }
if errors.Is(err, csrf.ErrForbidden)               { /* 403 */ }
if errors.Is(err, csrf.ErrMissingToken)            { /* 403 */ }
if errors.Is(err, csrf.ErrTokenNotFound)           { /* storage miss */ }
if errors.Is(err, jwt.ErrUnauthorized)             { /* 401 */ }
if errors.Is(err, jwt.ErrTokenInvalid)             { /* 401 */ }
if errors.Is(err, jwt.ErrTokenMissing)             { /* 401 */ }
if errors.Is(err, jwt.ErrTokenExpired)             { /* 401 */ }
if errors.Is(err, jwt.ErrTokenSignatureInvalid)    { /* 401 */ }
if errors.Is(err, jwt.ErrTokenMalformed)           { /* parse error */ }
if errors.Is(err, jwt.ErrTokenNotValidYet)         { /* nbf check */ }
if errors.Is(err, jwt.ErrTokenUnverifiable)        { /* no key */ }
if errors.Is(err, jwt.ErrTokenUsedBeforeIssued)    { /* iat check */ }
if errors.Is(err, jwt.ErrAlgNone)                  { /* alg:none attack */ }
if errors.Is(err, jwt.ErrInvalidIssuer)            { /* iss mismatch */ }
if errors.Is(err, jwt.ErrInvalidAudience)          { /* aud mismatch */ }
if errors.Is(err, jwt.ErrInvalidSubject)           { /* sub mismatch */ }
if errors.Is(err, bodylimit.ErrBodyTooLarge)       { /* 413 */ }
if errors.Is(err, timeout.ErrServiceUnavailable)   { /* 503 */ }
```

### Preemptive Timeout

```go
timeout.New(timeout.Config{
	Timeout:    3 * time.Second,
	Preemptive: true, // runs handler in goroutine, returns 503 on timeout
})
```

Race-free goroutine drain, panic recovery in the handler goroutine, depth-tracked response buffering.

### Security

- **Secure**: OWASP headers (HSTS HTTPS-only, CSP, COOP/CORP/COEP, X-XSS-Protection:0) pre-computed at init, zero allocs
- **KeyAuth**: `StaticKeys()` timing-safe with length-padded comparison, Bearer prefix stripping, multi-source fallback
- **CSRF**: Double-submit cookie with token reuse, Origin/Referer/Sec-Fetch-Site defense-in-depth, `TrustedOrigins`, buffered `crypto/rand`
- **JWT**: HMAC/RSA/ECDSA/EdDSA signing, kid rotation, JWKS auto-refresh (HTTPS-enforced, singleflight), ECDSA JWKS, `ClaimsFromContext[T]()`, `ClaimsFactory` for custom types, error wrapping
- **Session**: Pluggable `Store`, sharded `MemoryStore`, absolute + idle timeout, zero-arg `Regenerate`, cookie expiry on `Destroy`
- **Debug**: Localhost-only by default, memory stats, build info, route introspection
- **BasicAuth**: Timing-safe username-miss protection, deep-copied credential maps
- **Recovery**: Broken pipe detection, nested recovery catches ErrorHandler panics
- **CORS**: Multi-wildcard validation, spec-correct preflight detection
- **RateLimit**: NTP clock-step protection, sharded locks
- **RequestID**: Input validation (printable ASCII, 128 char max) prevents header/log injection
- **Logger**: Control character escaping (`\xHH`) prevents terminal escape injection

## Performance

### Single Middleware (Apple M5, arm64, median of 5 runs)

| Middleware | Celeris | Fiber v3 | Echo v4 | Chi v5 | net/http |
|-----------|---------|----------|---------|--------|----------|
| **Logger** | **318 ns / 0** | 301 / 2 | 1,152 / 16 | 1,270 / 29 | 1,273 / 13 |
| **Recovery** | **93 ns / 0** | 100 / 0 | 876 / 15 | 805 / 12 | 817 / 12 |
| **CORS Preflight** | **182 ns / 0** | 577 / 6 | 1,399 / 27 | 1,209 / 20 | 1,230 / 20 |
| **CORS Simple** | **94 ns / 0** | 185 / 0 | 1,066 / 20 | 971 / 16 | 996 / 16 |
| **RateLimit** | **174 ns / 1** | 327 / 5 | 1,052 / 17 | — | — |
| **RequestID** | **162 ns / 2** | 409 / 5 | 1,068 / 19 | 964 / 18 | 1,226 / 22 |
| **Timeout** | **661 ns / 8** | 1,046 / 10 | 2,012 / 33 | 1,033 / 17 | 1,929 / 25 |
| **BodyLimit** | **98 ns / 0** | — | 965 / 17 | — | 978 / 16 |
| **BasicAuth** | **143 ns / 2** | 263 / 3 | 1,012 / 19 | 924 / 15 | 945 / 15 |

Format: `ns/op / allocs`. **Celeris ranks 1st on all 9 benchmarks.**

### Multi-Middleware Chains

| Chain | Celeris | Fiber v3 | Echo v4 | Chi v5 | net/http |
|-------|---------|----------|---------|--------|----------|
| **API** (Recovery + RequestID + CORS + RateLimit) | **313 ns / 4** | 772 / 10 | 1,366 / 25 | 1,414 / 28 | 1,493 / 28 |
| **Auth** (Recovery + Logger + RequestID + BasicAuth) | **521 ns / 6** | 780 / 10 | 1,608 / 27 | 1,837 / 44 | 2,017 / 29 |

**2.5x faster than Fiber, 4.4x faster than Chi** on the API chain.

Benchmarks: [test/benchcmp/](./test/benchcmp/) | [Methodology](./test/benchcmp/README.md)

## Common Config Fields

Every `Config` struct supports:

| Field | Type | Description |
|-------|------|-------------|
| `Skip` | `func(*celeris.Context) bool` | Conditionally bypass the middleware |
| `SkipPaths` | `[]string` | Skip exact path matches (most middleware -- see individual package docs) |

## Testing

Use `celeristest` from the core framework for zero-overhead middleware testing:

```go
ctx, rec := celeristest.NewContextT(t, "GET", "/",
    celeristest.WithHeader("authorization", "Bearer "+token),
    celeristest.WithHandlers(myMiddleware, handler),
)
err := ctx.Next()
```

See the `*_test.go` files in each middleware package for comprehensive examples.

## Writing Custom Middleware

```go
func Timing() celeris.HandlerFunc {
	return func(c *celeris.Context) error {
		start := time.Now()
		err := c.Next()
		slog.Info("request", "path", c.Path(), "duration", time.Since(start))
		return err
	}
}
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full middleware authoring guide.

## Project Structure

```
logger/         Structured request logging (slog + FastHandler)
recovery/       Panic recovery with broken pipe detection
cors/           Cross-Origin Resource Sharing with O(1) origin matching
ratelimit/      Sharded token bucket rate limiter with ParseRate
requestid/      Request ID generation with input validation
timeout/        Request timeout with cooperative + preemptive modes
bodylimit/      Request body size enforcement with human-readable sizes
basicauth/      HTTP Basic auth with timing-safe comparison
secure/         OWASP security headers (0 allocs)
keyauth/        API key authentication with constant-time validation
csrf/           CSRF protection with double-submit cookie
session/        Session management with pluggable Store
debug/          Debug endpoints (localhost-only, memory, build, routes)
healthcheck/    Kubernetes liveness/readiness/startup probes
metrics/        Prometheus metrics [separate module]
jwt/            JWT authentication with zero-dep custom parser
otel/           OpenTelemetry tracing + metrics [separate module]
internal/       Shared test utilities
test/benchcmp/  Cross-framework benchmark comparison
```

## Contributing

```bash
go install github.com/magefile/mage@latest  # one-time setup
mage lint    # run linters
mage test    # run tests with race detector
mage bench   # run benchmarks
mage all     # full verification: lint + test + bench
```

Pull requests should target `main`. See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## License

[Apache License 2.0](LICENSE)
