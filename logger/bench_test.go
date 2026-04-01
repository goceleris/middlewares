package logger

import (
	"io"
	"log/slog"
	"testing"

	"github.com/goceleris/celeris/celeristest"
)

func BenchmarkLogger(b *testing.B) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := New(Config{Output: log})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, _ := celeristest.NewContext("GET", "/bench")
		_ = mw(ctx)
		celeristest.ReleaseContext(ctx)
	}
}

func BenchmarkLoggerFastHandler(b *testing.B) {
	log := slog.New(NewFastHandler(io.Discard, nil))
	mw := New(Config{Output: log})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, _ := celeristest.NewContext("GET", "/bench")
		_ = mw(ctx)
		celeristest.ReleaseContext(ctx)
	}
}

func BenchmarkLoggerSkipPath(b *testing.B) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := New(Config{Output: log, SkipPaths: []string{"/health"}})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, _ := celeristest.NewContext("GET", "/health")
		_ = mw(ctx)
		celeristest.ReleaseContext(ctx)
	}
}
