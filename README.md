# celeris middleware

[![CI](https://github.com/goceleris/middlewares/actions/workflows/ci.yml/badge.svg)](https://github.com/goceleris/middlewares/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/goceleris/middlewares.svg)](https://pkg.go.dev/github.com/goceleris/middlewares)
[![Go Report Card](https://goreportcard.com/badge/github.com/goceleris/middlewares)](https://goreportcard.com/report/github.com/goceleris/middlewares)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Production-ready middleware for [celeris](https://github.com/goceleris/celeris). Every middleware targets **zero allocations** on the hot path — 5 of 8 achieve 0 allocs/op. **#1 on all 11 benchmarks** across Fiber v3, Echo v4, Chi v5, Gin, and net/http.

## Middleware

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

## Quick Start

```
go get github.com/goceleris/middlewares
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
if errors.Is(err, ratelimit.ErrTooManyRequests) { /* 429 */ }
if errors.Is(err, basicauth.ErrUnauthorized)    { /* 401 */ }
if errors.Is(err, bodylimit.ErrBodyTooLarge)    { /* 413 */ }
if errors.Is(err, timeout.ErrServiceUnavailable){ /* 503 */ }
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

- **BasicAuth**: Timing-safe username-miss protection (fixed-length dummy compare), deep-copied credential maps, `ValidatorWithContext` for per-request auth decisions
- **Recovery**: Broken pipe / ECONNRESET detection (WARN-level, no stack trace), nested recovery catches ErrorHandler panics, `errors.Is` for `http.ErrAbortHandler`
- **CORS**: Multi-wildcard validation (panics on `https://*.*.example.com`), three wildcard conflict guards, spec-correct preflight detection
- **RateLimit**: NTP clock-step protection, sharded locks prevent single-mutex bottleneck
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
| `SkipPaths` | `[]string` | Skip exact path matches (logger, ratelimit, basicauth, timeout) |

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
