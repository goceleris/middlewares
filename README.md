# celeris middleware

[![CI](https://github.com/goceleris/middlewares/actions/workflows/ci.yml/badge.svg)](https://github.com/goceleris/middlewares/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/goceleris/middlewares.svg)](https://pkg.go.dev/github.com/goceleris/middlewares)
[![Go Report Card](https://goreportcard.com/badge/github.com/goceleris/middlewares)](https://goreportcard.com/report/github.com/goceleris/middlewares)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Production-ready middleware for [celeris](https://github.com/goceleris/celeris). Every middleware targets **zero allocations** on the hot path.

## Middleware

| Package | Description |
|---------|-------------|
| [logger](./logger/) | Structured request logging via `slog` |
| [recovery](./recovery/) | Panic recovery with stack trace capture |
| [cors](./cors/) | Cross-Origin Resource Sharing |
| [ratelimit](./ratelimit/) | Sharded token bucket rate limiting |
| [requestid](./requestid/) | Request ID generation and propagation |
| [timeout](./timeout/) | Request timeout enforcement |
| [bodylimit](./bodylimit/) | Request body size limiting |
| [basicauth](./basicauth/) | HTTP Basic authentication |

## Quick Start

```
go get github.com/goceleris/middlewares
```

Requires **Go 1.26+** and `github.com/goceleris/celeris` v1.2.1+.

## Usage

```go
package main

import (
	"log"

	"github.com/goceleris/celeris"
	"github.com/goceleris/middlewares/cors"
	"github.com/goceleris/middlewares/logger"
	"github.com/goceleris/middlewares/recovery"
)

func main() {
	s := celeris.New(celeris.Config{Addr: ":8080"})
	s.Use(recovery.New())
	s.Use(logger.New())
	s.Use(cors.New())
	s.GET("/", func(c *celeris.Context) error {
		return c.String(200, "Hello, World!")
	})
	log.Fatal(s.Start())
}
```

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

Every `Config` struct has a `Skip func(*celeris.Context) bool` field to conditionally bypass the middleware.

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

## Performance

Cross-framework comparison (Apple M5, arm64, median of 5 runs):

| Middleware | Celeris | Fiber v3 | Echo v4 | Chi v5 | net/http |
|-----------|---------|----------|---------|--------|----------|
| Logger | 723 ns | 301 ns | 1,180 ns | 1,315 ns | 1,280 ns |
| Recovery | 252 ns | 100 ns | 879 ns | 806 ns | 826 ns |
| CORS Preflight | 358 ns | 583 ns | 1,401 ns | 1,204 ns | 1,243 ns |
| CORS Simple | 322 ns | 189 ns | 1,080 ns | 956 ns | 1,001 ns |
| RateLimit | 405 ns | 326 ns | 1,060 ns | -- | -- |
| RequestID | 376 ns | 410 ns | 1,066 ns | 964 ns | 1,239 ns |
| Timeout | 749 ns | 1,041 ns | 2,041 ns | 1,051 ns | 1,931 ns |
| BasicAuth | 452 ns | 262 ns | 1,023 ns | 939 ns | 975 ns |

Benchmarks measure middleware overhead with a no-op handler. Each framework uses its native context creation at production-optimal settings. See the [benchmark comparison README](./test/benchcmp/README.md) for methodology and reproduction instructions.

## Project Structure

```
logger/         Structured request logging (slog)
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
