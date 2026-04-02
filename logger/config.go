package logger

import (
	"log/slog"
	"time"

	"github.com/goceleris/celeris"
)

// DefaultSensitiveHeaders lists header names redacted by default when
// SensitiveHeaders is nil (not explicitly set). Set SensitiveHeaders
// to an empty slice ([]string{}) to disable all redaction.
var DefaultSensitiveHeaders = []string{
	"authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
}

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

	// Done is called after the log entry is written. Useful for alerting
	// on 5xx responses or collecting metrics outside the log pipeline.
	Done func(c *celeris.Context, latency time.Duration, status int)

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
	//
	// When nil, DefaultSensitiveHeaders is used. Set to an empty slice
	// ([]string{}) to disable all redaction.
	SensitiveHeaders []string

	// TimeZone sets the timezone for log timestamps. Default nil uses
	// the local timezone.
	TimeZone *time.Location

	// TimeFormat sets a custom time format for FastHandler output.
	// Uses Go time layout syntax (e.g. time.RFC3339). When empty,
	// FastHandler uses its built-in RFC3339-millis formatter.
	TimeFormat string

	// LogHost includes the request Host header.
	LogHost bool
	// LogUserAgent includes the User-Agent header.
	LogUserAgent bool
	// LogReferer includes the Referer header.
	LogReferer bool
	// LogProtocol includes the request protocol (e.g., "HTTP/1.1").
	LogProtocol bool
	// LogRoute includes the matched route pattern (FullPath).
	LogRoute bool
	// LogPID includes the process ID as "pid" attr.
	LogPID bool
	// LogQueryParams includes the raw query string as "query" attr.
	LogQueryParams bool
	// LogFormValues includes form field names and values as "form" attr
	// (only when content-type is application/x-www-form-urlencoded).
	LogFormValues bool
	// LogCookies includes cookie names (not values, for security) as
	// "cookies" attr.
	LogCookies bool
	// LogBytesIn includes the request content length as "bytes_in" attr.
	LogBytesIn bool
	// LogScheme includes the request scheme (e.g., "https") as "scheme" attr.
	LogScheme bool
	// LogResponseHeaders lists specific response header names whose values
	// should be included in the log entry. Header names are matched
	// case-insensitively. Each matched header is logged as
	// "resp_header.<lowercased-name>".
	LogResponseHeaders []string

	// SensitiveFormFields lists form field names whose values should be
	// redacted when LogFormValues is true. Values are replaced with
	// "[REDACTED]". Field names are matched case-insensitively.
	// Default nil means no redaction.
	SensitiveFormFields []string
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
