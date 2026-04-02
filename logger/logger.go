package logger

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

var attrPool = sync.Pool{New: func() any {
	s := make([]slog.Attr, 0, 20)
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

	sensitiveMap := make(map[string]struct{}, len(cfg.SensitiveHeaders))
	for _, h := range cfg.SensitiveHeaders {
		sensitiveMap[strings.ToLower(h)] = struct{}{}
	}

	handler := cfg.Output.Handler()
	levelFn := cfg.Level
	fieldsFn := cfg.Fields
	captureReqBody := cfg.CaptureRequestBody
	captureRespBody := cfg.CaptureResponseBody
	maxCapture := cfg.MaxCaptureBytes
	logHost := cfg.LogHost
	logUserAgent := cfg.LogUserAgent
	logReferer := cfg.LogReferer
	logProtocol := cfg.LogProtocol
	logRoute := cfg.LogRoute

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		path := c.Path()
		if _, ok := skipMap[path]; ok {
			return c.Next()
		}

		if captureRespBody {
			c.CaptureResponse()
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
		if rid, ok := c.Get("request_id"); ok {
			if s, ok := rid.(string); ok && s != "" {
				attrs = append(attrs, slog.String("request_id", s))
			}
		} else if rid := c.Header("x-request-id"); rid != "" {
			attrs = append(attrs, slog.String("request_id", rid))
		}
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		if logHost {
			if h := c.Host(); h != "" {
				attrs = append(attrs, slog.String("host", h))
			}
		}
		if logUserAgent {
			if ua := c.Header("user-agent"); ua != "" {
				attrs = append(attrs, slog.String("user_agent", ua))
			}
		}
		if logReferer {
			if ref := c.Header("referer"); ref != "" {
				attrs = append(attrs, slog.String("referer", ref))
			}
		}
		if logProtocol {
			if proto := c.Header(":protocol"); proto != "" {
				attrs = append(attrs, slog.String("protocol", proto))
			}
		}
		if logRoute {
			if fp := c.FullPath(); fp != "" {
				attrs = append(attrs, slog.String("route", fp))
			}
		}
		if fieldsFn != nil {
			attrs = append(attrs, fieldsFn(c, latency)...)
		}
		if captureReqBody {
			body := c.Body()
			if len(body) > maxCapture {
				body = body[:maxCapture]
			}
			attrs = append(attrs, slog.String("request_body", string(body)))
		}
		if captureRespBody {
			body := c.ResponseBody()
			if len(body) > maxCapture {
				body = body[:maxCapture]
			}
			attrs = append(attrs, slog.String("response_body", string(body)))
		}
		if len(sensitiveMap) > 0 {
			for _, kv := range c.RequestHeaders() {
				key := strings.ToLower(kv[0])
				if _, ok := sensitiveMap[key]; ok {
					attrs = append(attrs, slog.String("header."+key, "[REDACTED]"))
				}
			}
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
