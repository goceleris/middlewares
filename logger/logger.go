package logger

import (
	"log/slog"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

var attrPool = sync.Pool{New: func() any {
	s := make([]slog.Attr, 0, 12)
	return &s
}}

// New creates a logger middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	handler := cfg.Output.Handler()
	levelFn := cfg.Level
	fieldsFn := cfg.Fields

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		path := c.Path()
		if _, ok := skipMap[path]; ok {
			return c.Next()
		}

		start := time.Now()
		err := c.Next()
		latency := time.Since(start)

		status := c.StatusCode()
		level := levelFn(status)

		ctx := c.Context()
		if !handler.Enabled(ctx, level) {
			return err
		}

		attrsPtr := attrPool.Get().(*[]slog.Attr)
		attrs := (*attrsPtr)[:0]

		attrs = append(attrs,
			slog.String("method", c.Method()),
			slog.String("path", path),
			slog.Int("status", status),
			slog.Duration("latency", latency),
			slog.Int("bytes", c.BytesWritten()),
		)

		if ip := c.ClientIP(); ip != "" {
			attrs = append(attrs, slog.String("client_ip", ip))
		}
		if rid := c.Header("x-request-id"); rid != "" {
			attrs = append(attrs, slog.String("request_id", rid))
		}
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		if fieldsFn != nil {
			attrs = append(attrs, fieldsFn(c, latency)...)
		}

		// Call handler directly instead of log.LogAttrs to skip
		// runtime.Callers (stack walk) and the redundant time.Now()
		// inside slog.Logger.logAttrs. We reuse the middleware's
		// start time as the record timestamp.
		r := slog.NewRecord(start, level, "request", 0)
		r.AddAttrs(attrs...)
		_ = handler.Handle(ctx, r)

		*attrsPtr = attrs
		attrPool.Put(attrsPtr)

		return err
	}
}
