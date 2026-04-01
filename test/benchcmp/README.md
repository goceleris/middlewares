# celeris middleware benchmark comparison

Cross-framework middleware performance comparison. Measures pure middleware overhead with a no-op handler across Celeris, Fiber v3, Echo v4, Chi v5, and net/http stdlib.

## Frameworks

| Framework | Context Model | Middleware Pattern |
|-----------|---------------|-------------------|
| [Celeris](https://github.com/goceleris/celeris) | Pooled `Context` via `celeristest` | `func(*Context) error` + `c.Next()` |
| [Fiber v3](https://github.com/gofiber/fiber) | Pooled `fasthttp.RequestCtx` + Fiber context | `func(Ctx) error` + `c.Next()` |
| [Echo v4](https://github.com/labstack/echo) | `e.NewContext(req, rec)` per iteration | `func(Context) error` + `next(c)` |
| [Chi v5](https://github.com/go-chi/chi) | `httptest.NewRequest` + `httptest.NewRecorder` | `func(http.Handler) http.Handler` |
| net/http | `httptest.NewRequest` + `httptest.NewRecorder` | `func(http.Handler) http.Handler` |

## Middleware Coverage

| Middleware | Celeris | Fiber | Echo | Chi | Stdlib |
|-----------|---------|-------|------|-----|--------|
| Logger | ours | `fiber/middleware/logger` | `echo/middleware.Logger` | `chi/middleware.Logger` | custom `slog` wrapper |
| Recovery | ours | `fiber/middleware/recover` | `echo/middleware.Recover` | `chi/middleware.Recoverer` | custom `defer`/`recover` |
| CORS | ours | `fiber/middleware/cors` | `echo/middleware.CORS` | `rs/cors` | `rs/cors` |
| RateLimit | ours | `fiber/middleware/limiter` | `echo/middleware.RateLimiter` | -- | -- |
| RequestID | ours | `fiber/middleware/requestid` | `echo/middleware.RequestID` | `chi/middleware.RequestID` | custom UUID |
| Timeout | ours | `fiber/middleware/timeout` | `echo/middleware.Timeout` | `chi/middleware.Timeout` | `http.TimeoutHandler` |
| BodyLimit | ours | -- | `echo/middleware.BodyLimit` | -- | `http.MaxBytesHandler` |
| BasicAuth | ours | `fiber/middleware/basicauth` | `echo/middleware.BasicAuth` | custom | custom |

## Running

```bash
go test -bench=. -benchmem -count=5 -run=^$ -timeout=600s ./...
```

Single framework:

```bash
go test -bench='_Celeris' -benchmem -count=5 -run=^$ ./...
go test -bench='_Fiber'   -benchmem -count=5 -run=^$ ./...
```

## Methodology

- Each benchmark creates the framework's test context, wraps a **no-op handler** with the middleware, and measures the round-trip overhead
- Celeris and Fiber pool their contexts (production behavior); Echo/Chi/stdlib allocate per iteration (their production behavior)
- All middleware configured equivalently: output to `io.Discard`, stack traces disabled, wildcard CORS, effectively-unlimited rate limits, 5s timeouts, constant-time auth comparison
- `b.ReportAllocs()` on all benchmarks; `b.Loop()` pattern (Go 1.26)

## Interpreting Results

| Metric | Meaning |
|--------|---------|
| **ns/op** | Nanoseconds per operation (lower is better) |
| **B/op** | Bytes allocated per operation (lower is better) |
| **allocs/op** | Heap allocations per operation (0 is ideal) |

Allocation counts include context creation overhead, which varies by framework. To isolate middleware-only cost, compare against a baseline benchmark with no middleware.

## Module

This is a **separate Go module** (`test/benchcmp/go.mod`) to isolate external framework dependencies from the root `github.com/goceleris/middlewares` module. Third-party deps (Fiber, Echo, Chi, rs/cors) do not leak into the main module's dependency tree.
