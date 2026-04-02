package logger

import (
	"log/slog"
	"time"

	"github.com/goceleris/celeris"
)

// Config defines the logger middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Output is the slog logger to use. Default: slog.Default().
	Output *slog.Logger

	// Level maps a response status code to a log level.
	// Default: 5xx→Error, 4xx→Warn, else→Info.
	Level func(status int) slog.Level

	// Fields adds custom fields to the log entry.
	Fields func(c *celeris.Context, latency time.Duration) []slog.Attr

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// CaptureRequestBody logs the request body (truncated to MaxCaptureBytes).
	CaptureRequestBody bool

	// CaptureResponseBody logs the response body (truncated to MaxCaptureBytes).
	// Requires the response to be captured via c.CaptureResponse().
	CaptureResponseBody bool

	// MaxCaptureBytes is the maximum number of body bytes to log.
	// Default: 4096. Prevents OOM on large request/response bodies.
	MaxCaptureBytes int

	// SensitiveHeaders lists header names whose values should be redacted
	// in log output. Values are replaced with "[REDACTED]". Header names
	// are matched case-insensitively.
	SensitiveHeaders []string
}

// DefaultConfig is the default logger configuration.
var DefaultConfig = Config{}

func applyDefaults(cfg Config) Config {
	if cfg.Output == nil {
		cfg.Output = slog.Default()
	}
	if cfg.Level == nil {
		cfg.Level = defaultLevel
	}
	if cfg.MaxCaptureBytes <= 0 && (cfg.CaptureRequestBody || cfg.CaptureResponseBody) {
		cfg.MaxCaptureBytes = 4096
	}
	return cfg
}

func defaultLevel(status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	case status >= 400:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

func (cfg Config) validate() {}
