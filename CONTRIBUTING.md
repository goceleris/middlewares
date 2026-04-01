# Contributing to Celeris Middleware

Thank you for your interest in contributing to celeris middleware!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/middlewares.git`
3. Install dependencies: `go mod download`
4. Run checks: `mage all`

## Development

### Prerequisites

- Go 1.26+
- [Mage](https://magefile.org) build tool: `go install github.com/magefile/mage@latest`

### Build & Test

```bash
mage lint      # Run linters
mage test      # Run tests with race detection
mage bench     # Run benchmarks
mage all       # Run all checks
```

## Adding a New Middleware

1. Create a directory: `yourmiddleware/`
2. Follow the standard file structure:

```
yourmiddleware/
├── config.go               # Config struct + DefaultConfig + applyDefaults + validate
├── yourmiddleware.go        # New() function + middleware logic
├── yourmiddleware_test.go   # Unit tests + fuzz tests
└── bench_test.go            # Benchmarks + zero-alloc enforcement
```

3. Every middleware must:
   - Export `New(config ...Config) celeris.HandlerFunc`
   - Export `Config` struct with `Skip func(*celeris.Context) bool` field
   - Export `DefaultConfig` variable
   - Pre-compute everything possible in `New()`, not per-request
   - Achieve **0 allocs/op** on the hot path
   - Include unit tests, fuzz tests, and benchmark tests

### Config Pattern

```go
var DefaultConfig = Config{
    // sensible defaults
}

func New(config ...Config) celeris.HandlerFunc {
    cfg := DefaultConfig
    if len(config) > 0 {
        cfg = config[0]
    }
    cfg = applyDefaults(cfg)
    cfg.validate()
    // pre-compute ...
    return func(c *celeris.Context) error {
        if cfg.Skip != nil && cfg.Skip(c) {
            return c.Next()
        }
        // middleware logic
        return c.Next()
    }
}
```

### Testing

Use `internal/testutil` helpers:

```go
func TestMyMiddleware(t *testing.T) {
    mw := New()
    rec, err := testutil.RunMiddleware(t, mw)
    testutil.AssertNoError(t, err)
    testutil.AssertStatus(t, rec, 200)
}
```

For middleware chain testing:

```go
func TestMyMiddlewareChain(t *testing.T) {
    mw := New()
    handler := func(c *celeris.Context) error {
        return c.String(200, "ok")
    }
    rec, err := testutil.RunChain(t, []celeris.HandlerFunc{mw, handler}, "GET", "/")
    testutil.AssertNoError(t, err)
    testutil.AssertStatus(t, rec, 200)
}
```

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new functionality
- Run `mage all` before submitting
- Follow existing code style (enforced by golangci-lint)
- Write clear commit messages

## Code Style

- Follow standard Go conventions
- No unnecessary comments — code should be self-documenting
- Use `mage lint` to verify

## Reporting Issues

Use GitHub Issues with the provided templates for bug reports and feature requests.
