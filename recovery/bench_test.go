package recovery

import (
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"
)

func BenchmarkRecoveryNoPanic(b *testing.B) {
	mw := New(Config{LogStack: false})
	noop := func(c *celeris.Context) error { return nil }
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, _ := celeristest.NewContext("GET", "/bench", celeristest.WithHandlers(mw, noop))
		ctx.Next()
		celeristest.ReleaseContext(ctx)
	}
}

func BenchmarkRecoveryWithPanic(b *testing.B) {
	mw := New(Config{LogStack: false})
	panicker := func(c *celeris.Context) error { panic("bench") }
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, _ := celeristest.NewContext("GET", "/bench", celeristest.WithHandlers(mw, panicker))
		ctx.Next()
		celeristest.ReleaseContext(ctx)
	}
}
