# celeris middleware

[![CI](https://github.com/goceleris/middlewares/actions/workflows/ci.yml/badge.svg)](https://github.com/goceleris/middlewares/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/goceleris/middlewares.svg)](https://pkg.go.dev/github.com/goceleris/middlewares)
[![Go Report Card](https://goreportcard.com/badge/github.com/goceleris/middlewares)](https://goreportcard.com/report/github.com/goceleris/middlewares)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Production-ready middleware for [celeris](https://github.com/goceleris/celeris). Every middleware targets **zero allocations** on the hot path — 6 of 9 benchmarks achieve 0 allocs/op.

## Middleware

| Package | Description | Allocs |
|---------|-------------|--------|
| [logger](./logger/) | Structured request logging via `slog` with zero-alloc [FastHandler](./logger/fasthandler.go) | 0 |
| [recovery](./recovery/) | Panic recovery with configurable stack capture | 0 |
| [cors](./cors/) | Cross-Origin Resource Sharing with pre-computed headers | 0 |
| [ratelimit](./ratelimit/) | Sharded token-bucket rate limiting per client IP | 1 |
| [requestid](./requestid/) | UUID v4 request ID with buffered random source | 2 |
| [timeout](./timeout/) | Request timeout via `context.WithTimeout` | 8 |
| [bodylimit](./bodylimit/) | Request body size enforcement via Content-Length | 0 |
| [basicauth](./basicauth/) | HTTP Basic Authentication with constant-time comparison | 2 |

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

	"github.com/goceleris/celeris"
	"github.com/goceleris/middlewares/cors"
	"github.com/goceleris/middlewares/logger"
	"github.com/goceleris/middlewares/recovery"
	"github.com/goceleris/middlewares/requestid"
)

func main() {
	s := celeris.New(celeris.Config{Addr: ":8080"})

	// Zero-alloc logging with FastHandler
	s.Use(recovery.New())
	s.Use(logger.New(logger.Config{
		Output: slog.New(logger.NewFastHandler(os.Stderr, nil)),
	}))
	s.Use(requestid.New())
	s.Use(cors.New())

	s.GET("/", func(c *celeris.Context) error {
		return c.String(200, "Hello, World!")
	})
	log.Fatal(s.Start())
}
```

## FastHandler — Zero-Alloc slog.Handler

The `logger` package includes `FastHandler`, a high-performance `slog.Handler` that formats log records directly into pooled byte buffers with zero allocations in steady state. It's a drop-in replacement for `slog.TextHandler`:

```go
// Standard slog (slower, allocates internally)
log := slog.New(slog.NewTextHandler(os.Stderr, nil))

// FastHandler (zero-alloc, 40% faster)
log := slog.New(logger.NewFastHandler(os.Stderr, nil))
```

FastHandler is 100% `slog.Handler` compatible — works with `slog.With()`, `slog.WithGroup()`, and all slog tooling.

## Middleware Configuration

Every middleware follows the same pattern: `New(config ...Config)` with sensible defaults. Pass zero arguments for defaults, or provide a `Config` struct to customize:

```go
s.Use(cors.New(cors.Config{
	AllowOrigins:     []string{"https://example.com"},
	AllowCredentials: true,
	MaxAge:           3600,
}))

s.Use(ratelimit.New(ratelimit.Config{
	RPS:   100,
	Burst: 200,
}))

s.Use(basicauth.New(basicauth.Config{
	Validator: func(user, pass string) bool {
		return subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte("secret")) == 1
	},
}))
```

### Common Config Fields

Every `Config` struct supports:

| Field | Type | Description |
|-------|------|-------------|
| `Skip` | `func(*celeris.Context) bool` | Conditionally bypass the middleware |
| `SkipPaths` | `[]string` | Skip exact path matches (available on logger, ratelimit, basicauth, timeout) |

## Performance

### Single Middleware (Apple M5, arm64, median of 5 runs)

| Middleware | Celeris | Fiber v3 | Echo v4 | Chi v5 | net/http |
|-----------|---------|----------|---------|--------|----------|
| **Logger** | **282 ns / 0** | 300 / 2 | 1,385 / 16 | 1,896 / 29 | 1,482 / 13 |
| **Recovery** | **53 ns / 0** | 100 / 0 | 1,090 / 15 | 1,408 / 12 | 990 / 12 |
| **CORS Preflight** | **112 ns / 0** | 583 / 6 | 1,756 / 27 | 1,812 / 20 | 1,533 / 20 |
| **CORS Simple** | **66 ns / 0** | 185 / 0 | 1,359 / 20 | 1,397 / 16 | 1,204 / 16 |
| **RateLimit** | **144 ns / 1** | 326 / 5 | 1,330 / 17 | — | — |
| **RequestID** | **127 ns / 2** | 411 / 5 | 1,312 / 19 | 1,353 / 18 | 1,467 / 22 |
| **Timeout** | **651 ns / 8** | 1,033 / 10 | 2,346 / 33 | 1,321 / 17 | 2,161 / 25 |
| **BodyLimit** | **66 ns / 0** | — | 1,192 / 17 | — | 1,241 / 17 |
| **BasicAuth** | **113 ns / 2** | 266 / 3 | 1,239 / 19 | 1,148 / 15 | 1,191 / 15 |

Format: `ns/op / allocs`. **Celeris ranks 1st on all 9 benchmarks.**

### Multi-Middleware Chains (realistic production stacks)

| Chain | Celeris | Fiber v3 | Echo v4 | Chi v5 | net/http |
|-------|---------|----------|---------|--------|----------|
| **API** (Recovery + RequestID + CORS + RateLimit) | **309 ns / 4** | 768 / 10 | 1,291 / 25 | 1,359 / 28 | 1,507 / 28 |
| **Auth** (Recovery + Logger + RequestID + BasicAuth) | **501 ns / 5** | 812 / 10 | 1,584 / 27 | 1,814 / 44 | 1,986 / 29 |

Multi-middleware overhead compounds linearly in other frameworks. Celeris's zero-alloc infrastructure means chain cost is dominated by actual middleware work, not framework overhead.

Benchmarks measure middleware overhead with a no-op handler. Each framework uses its native context creation at production-optimal settings. See the [benchmark methodology](./test/benchcmp/README.md) for reproduction instructions.

## Writing Custom Middleware

Middleware is a `celeris.HandlerFunc` that calls `c.Next()`:

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
recovery/       Panic recovery with optional stack capture
cors/           Cross-Origin Resource Sharing
ratelimit/      Sharded token bucket rate limiter
requestid/      Request ID generation and propagation
timeout/        Request timeout via context.WithTimeout
bodylimit/      Request body size enforcement
basicauth/      HTTP Basic authentication
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
