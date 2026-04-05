# DEPRECATED — Moved to github.com/goceleris/celeris

> **This repository has been archived.** All middleware packages have been merged into the main [celeris](https://github.com/goceleris/celeris) repository under `middleware/`.

## Migration

Replace your imports:

```diff
- import "github.com/goceleris/middlewares/cors"
+ import "github.com/goceleris/celeris/middleware/cors"

- import "github.com/goceleris/middlewares/jwt"
+ import "github.com/goceleris/celeris/middleware/jwt"
```

For middleware with external dependencies:

```diff
- import "github.com/goceleris/middlewares/metrics"
+ import "github.com/goceleris/celeris/middleware/metrics"

- import "github.com/goceleris/middlewares/otel"
+ import "github.com/goceleris/celeris/middleware/otel"
```

Then update your `go.mod`:

```sh
go get github.com/goceleris/celeris@latest
go mod tidy
```

## Why?

Middleware packages are now part of the main celeris module to enable:
- Atomic versioning (middleware always compatible with core)
- Simpler dependency management (one `go get` instead of two)
- Tighter integration (middleware can use internal APIs)
