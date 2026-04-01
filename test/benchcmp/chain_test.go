package benchcmp

// Chain benchmarks test realistic middleware stacks across frameworks.
// Each chain represents a common production configuration.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goceleris/celeris/celeristest"
	"github.com/goceleris/middlewares/basicauth"
	"github.com/goceleris/middlewares/cors"
	"github.com/goceleris/middlewares/logger"
	"github.com/goceleris/middlewares/ratelimit"
	"github.com/goceleris/middlewares/recovery"
	"github.com/goceleris/middlewares/requestid"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/gofiber/fiber/v3"
	fiberbasicauth "github.com/gofiber/fiber/v3/middleware/basicauth"
	fibercors "github.com/gofiber/fiber/v3/middleware/cors"
	fiberlimiter "github.com/gofiber/fiber/v3/middleware/limiter"
	fiberlogger "github.com/gofiber/fiber/v3/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v3/middleware/recover"
	fiberrequestid "github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	rscors "github.com/rs/cors"
)

// ---------------------------------------------------------------------------
// Chain A: Public API — Recovery + RequestID + CORS + RateLimit + handler
// This is a typical middleware stack for a public-facing API endpoint.
// ---------------------------------------------------------------------------

func BenchmarkChainAPI_Celeris(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rec := recovery.New(recovery.Config{LogStack: false})
	rid := requestid.New()
	co := cors.New()
	rl := ratelimit.New(ratelimit.Config{
		RPS: 1e9, Burst: 1e9, CleanupContext: ctx,
	})

	opts := []celeristest.Option{
		celeristest.WithHeader("origin", "http://example.com"),
		celeristest.WithHeader("x-forwarded-for", "1.2.3.4"),
		celeristest.WithHandlers(rec, rid, co, rl, noop),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c, _ := celeristest.NewContext("GET", "/api/users", opts...)
		c.Next()
		celeristest.ReleaseContext(c)
	}
}

func BenchmarkChainAPI_Fiber(b *testing.B) {
	h := fiberApp(func(app *fiber.App) {
		app.Use(fiberrecover.New())
		app.Use(fiberrequestid.New())
		app.Use(fibercors.New(fibercors.Config{AllowOrigins: []string{"*"}}))
		app.Use(fiberlimiter.New(fiberlimiter.Config{
			Max: int(1e9), Expiration: time.Hour,
		}))
		app.Get("/api/users", func(c fiber.Ctx) error { return nil })
	})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		fctx := acquireFctx(fiber.MethodGet, "/api/users")
		fctx.Request.Header.Set("Origin", "http://example.com")
		fctx.Request.Header.Set("X-Forwarded-For", "1.2.3.4")
		h(fctx)
		releaseFctx(fctx)
	}
}

func BenchmarkChainAPI_Echo(b *testing.B) {
	e := echo.New()
	e.Use(echomw.Recover())
	e.Use(echomw.RequestID())
	e.Use(echomw.CORSWithConfig(echomw.CORSConfig{AllowOrigins: []string{"*"}}))
	e.Use(echomw.RateLimiterWithConfig(echomw.RateLimiterConfig{
		Store: echomw.NewRateLimiterMemoryStore(1e9),
	}))
	e.GET("/api/users", func(c echo.Context) error { return nil })

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
	}
}

func BenchmarkChainAPI_Chi(b *testing.B) {
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestID)
	r.Use(rscors.New(rscors.Options{AllowedOrigins: []string{"*"}}).Handler)
	// Chi has no built-in rate limiter; skip to keep comparison fair
	r.Get("/api/users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
}

func BenchmarkChainAPI_Stdlib(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	// stdlib chain: recovery → requestid → cors
	chain := stdlibRecovery(stdlibRequestID(
		rscors.New(rscors.Options{AllowedOrigins: []string{"*"}}).Handler(handler),
	))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
	}
}

// ---------------------------------------------------------------------------
// Chain B: Authenticated API — Recovery + Logger + RequestID + BasicAuth + handler
// This is a typical middleware stack for an authenticated internal API.
// ---------------------------------------------------------------------------

func BenchmarkChainAuth_Celeris(b *testing.B) {
	rec := recovery.New(recovery.Config{LogStack: false})
	log := logger.New(logger.Config{
		Output: slog.New(logger.NewFastHandler(io.Discard, nil)),
	})
	rid := requestid.New()
	auth := basicauth.New(basicauth.Config{
		Validator: func(user, pass string) bool {
			return subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1 &&
				subtle.ConstantTimeCompare([]byte(pass), []byte("secret")) == 1
		},
	})

	opts := []celeristest.Option{
		celeristest.WithBasicAuth("admin", "secret"),
		celeristest.WithHandlers(rec, log, rid, auth, noop),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c, _ := celeristest.NewContext("GET", "/admin/dashboard", opts...)
		c.Next()
		celeristest.ReleaseContext(c)
	}
}

func BenchmarkChainAuth_Fiber(b *testing.B) {
	h := fiberApp(func(app *fiber.App) {
		app.Use(fiberrecover.New())
		app.Use(fiberlogger.New(fiberlogger.Config{Stream: io.Discard}))
		app.Use(fiberrequestid.New())
		app.Use(fiberbasicauth.New(fiberbasicauth.Config{
			Users: map[string]string{"admin": "secret"},
			Authorizer: func(user, pass string, _ fiber.Ctx) bool {
				return subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1 &&
					subtle.ConstantTimeCompare([]byte(pass), []byte("secret")) == 1
			},
		}))
		app.Get("/admin/dashboard", func(c fiber.Ctx) error { return nil })
	})
	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		fctx := acquireFctx(fiber.MethodGet, "/admin/dashboard")
		fctx.Request.Header.Set("Authorization", creds)
		h(fctx)
		releaseFctx(fctx)
	}
}

func BenchmarkChainAuth_Echo(b *testing.B) {
	e := echo.New()
	e.Use(echomw.Recover())
	e.Use(echomw.LoggerWithConfig(echomw.LoggerConfig{Output: io.Discard}))
	e.Use(echomw.RequestID())
	e.Use(echomw.BasicAuth(func(user, pass string, _ echo.Context) (bool, error) {
		return subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte("secret")) == 1, nil
	}))
	e.GET("/admin/dashboard", func(c echo.Context) error { return nil })

	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		req.Header.Set("Authorization", creds)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
	}
}

func BenchmarkChainAuth_Chi(b *testing.B) {
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestLogger(&chimw.DefaultLogFormatter{Logger: log.New(io.Discard, "", 0), NoColor: true}))
	r.Use(chimw.RequestID)
	r.Use(chiBasicAuth("admin", "secret"))
	r.Get("/admin/dashboard", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		req.Header.Set("Authorization", creds)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
}

func BenchmarkChainAuth_Stdlib(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	chain := stdlibRecovery(stdlibLogger(stdlibRequestID(
		stdlibBasicAuth("admin", "secret", handler),
	)))

	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		req.Header.Set("Authorization", creds)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
	}
}

// ---------------------------------------------------------------------------
// Stdlib middleware helpers for chain benchmarks
// ---------------------------------------------------------------------------

func stdlibRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rv := recover(); rv != nil {
				w.WriteHeader(500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func stdlibRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf [16]byte
		_, _ = rand.Read(buf[:])
		id := fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r)
	})
}

func stdlibLogger(next http.Handler) http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Duration("latency", time.Since(start)),
		)
	})
}

func stdlibBasicAuth(user, pass string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Basic "
		if !strings.HasPrefix(auth, prefix) {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			w.WriteHeader(401)
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			w.WriteHeader(401)
			return
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			w.WriteHeader(401)
			return
		}
		if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(parts[1]), []byte(pass)) != 1 {
			w.WriteHeader(401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// chiBasicAuth returns a chi-compatible BasicAuth middleware.
func chiBasicAuth(user, pass string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return stdlibBasicAuth(user, pass, next)
	}
}
