package benchcmp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rscors "github.com/rs/cors"
)

// --- stdlib middleware helpers (unexported, zero external deps) ---

// statusWriter wraps http.ResponseWriter to capture status code and bytes
// written, which is necessary for any stdlib logger middleware to report
// the same fields as framework loggers (method, path, status, latency, bytes).
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	return n, err
}

func stdlibLoggerMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			log.LogAttrs(r.Context(), slog.LevelInfo, "request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Duration("latency", time.Since(start)),
				slog.Int("bytes", sw.written),
			)
		})
	}
}

func stdlibRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func stdlibRequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf [16]byte
		_, _ = rand.Read(buf[:])
		id := fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

func stdlibBasicAuthMiddleware(user, pass string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if len(auth) < 7 || auth[:6] != "Basic " {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			decoded, err := base64.StdEncoding.DecodeString(auth[6:])
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			parts := string(decoded)
			var u, p string
			for i := range parts {
				if parts[i] == ':' {
					u, p = parts[:i], parts[i+1:]
					break
				}
			}
			if subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

var stdlibNoop = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

// --- Benchmarks ---

func BenchmarkLogger_Stdlib(b *testing.B) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := stdlibLoggerMiddleware(log)(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkRecovery_Stdlib(b *testing.B) {
	handler := stdlibRecoveryMiddleware(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkCORS_Stdlib_Preflight(b *testing.B) {
	c := rscors.New(rscors.Options{AllowedOrigins: []string{"*"}})
	handler := c.Handler(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("OPTIONS", "/bench", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkCORS_Stdlib_Simple(b *testing.B) {
	c := rscors.New(rscors.Options{AllowedOrigins: []string{"*"}})
	handler := c.Handler(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		req.Header.Set("Origin", "http://example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkRequestID_Stdlib(b *testing.B) {
	handler := stdlibRequestIDMiddleware(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkTimeout_Stdlib(b *testing.B) {
	handler := http.TimeoutHandler(stdlibNoop, 5*time.Second, "timeout")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkBodyLimit_Stdlib(b *testing.B) {
	handler := http.MaxBytesHandler(stdlibNoop, 1<<20)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("POST", "/bench", nil)
		req.Header.Set("Content-Length", "1024")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkSecure_Stdlib(b *testing.B) {
	handler := stdlibSecureHeaders(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkKeyAuth_Stdlib(b *testing.B) {
	handler := stdlibKeyAuth("test-api-key", stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		req.Header.Set("X-Api-Key", "test-api-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkCSRF_Stdlib(b *testing.B) {
	handler := stdlibCSRF(stdlibNoop)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkBasicAuth_Stdlib(b *testing.B) {
	handler := stdlibBasicAuthMiddleware("admin", "secret")(stdlibNoop)
	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("GET", "/bench", nil)
		req.Header.Set("Authorization", creds)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
