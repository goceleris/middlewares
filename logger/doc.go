// Package logger provides HTTP request logging middleware for celeris.
//
// The middleware logs each request with configurable fields including
// method, path, status, latency, and bytes written. It supports
// both standard slog handlers and the zero-alloc [FastHandler].
//
// Basic usage with the default slog output:
//
//	server.Use(logger.New())
//
// Using the zero-alloc FastHandler with color output:
//
//	mw := logger.New(logger.Config{
//	    Output: slog.New(logger.NewFastHandler(os.Stderr, &logger.FastHandlerOptions{
//	        Color: true,
//	    })),
//	})
//	server.Use(mw)
//
// [NewFastHandler] creates a [FastHandler] that formats log records
// directly into a pooled byte buffer, producing output compatible with
// slog.TextHandler. When [FastHandlerOptions].Color is true, status codes,
// HTTP methods, and latency values are colored with ANSI escape codes
// (e.g., green for 2xx, red for 5xx). Set [Config].DisableColors to true
// to suppress ANSI codes regardless of the Color option — useful for log
// files or CI environments. Set [Config].ForceColors to true to force ANSI
// output even when DisableColors would normally suppress it (e.g., testing
// color output in CI). Configure its minimum level via
// [FastHandlerOptions].
//
// # Body Capture
//
// Set [Config].CaptureRequestBody and/or [Config].CaptureResponseBody to
// log request and response bodies. Bodies are truncated to
// [Config].MaxCaptureBytes (default 4096).
//
//	server.Use(logger.New(logger.Config{
//	    CaptureRequestBody:  true,
//	    CaptureResponseBody: true,
//	    MaxCaptureBytes:     2048,
//	}))
//
// # Sensitive Header Redaction
//
// [Config].SensitiveHeaders lists header names whose values should be
// redacted in log output. Values are replaced with "[REDACTED]". Header
// names are matched case-insensitively. Use this to prevent credentials,
// tokens, or other secrets from appearing in logs:
//
//	server.Use(logger.New(logger.Config{
//	    SensitiveHeaders: []string{"Authorization", "Cookie"},
//	}))
//
// When SensitiveHeaders is nil, [DefaultSensitiveHeaders] is used
// automatically. Set it to an empty slice ([]string{}) to disable all
// header redaction.
//
// # Sensitive Form Field Redaction
//
// [Config].SensitiveFormFields lists form field names whose values should
// be redacted when [Config].LogFormValues is true. Unlike SensitiveHeaders,
// a nil SensitiveFormFields means NO redaction — all form values are logged
// as-is. This asymmetry is intentional: headers always contain well-known
// credential fields (Authorization, Cookie), while form field names are
// application-specific. Use [DefaultSensitiveFormFields] to get a
// reasonable starting list:
//
//	server.Use(logger.New(logger.Config{
//	    LogFormValues:       true,
//	    SensitiveFormFields: logger.DefaultSensitiveFormFields(),
//	}))
//
// # Request ID Integration
//
// The middleware automatically reads the request ID from the context store
// (key "request_id") first, falling back to the x-request-id header.
// This integrates seamlessly with the requestid middleware when both are
// installed. Additional fields can be added via [Config].Fields.
//
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
//
// # Predefined Configurations
//
// [CLFConfig] returns a Config for Common Log Format (CLF) style output,
// enabling LogHost, LogUserAgent, and LogReferer with a Fields callback
// that emits a traditional combined log format line.
//
// [JSONConfig] returns a Config for structured JSON output using
// slog.JSONHandler, enabling LogHost, LogUserAgent, LogReferer,
// LogRoute, and LogQueryParams.
//
// Both constructors return a [Config] value that can be further customized
// before passing to [New]:
//
//	cfg := logger.CLFConfig()
//	cfg.SkipPaths = []string{"/health"}
//	server.Use(logger.New(cfg))
//
// # Design Rationale: slog-Based, No Template Strings
//
// This middleware deliberately does NOT provide a template/format string
// system (e.g., "${method} ${path} ${status}"). Instead, all output is
// structured through Go's standard [log/slog] package:
//
//   - Structured logging is grep-friendly, machine-parseable, and integrates
//     with observability stacks (Datadog, Grafana, CloudWatch) out of the box.
//   - The [Config].Fields callback provides arbitrary extensibility without
//     inventing a DSL — callers use plain Go to add any slog.Attr they need.
//   - Template engines add parsing overhead and allocation pressure that
//     conflicts with the zero-alloc goal of [FastHandler].
//   - [CLFConfig] and [JSONConfig] cover the two most common pre-built
//     formats. Custom formats are achieved by choosing the slog.Handler
//     (TextHandler, JSONHandler, or third-party) and toggling Config fields.
//
// # Performance
//
// [FastHandler] formats log records directly into a pooled byte buffer,
// avoiding fmt.Sprintf and time.Format entirely. Timestamps are rendered
// with a hand-rolled RFC 3339 formatter, and integer/duration/bool values
// use strconv.Append* functions. The default configuration with no opt-in
// fields (LogHost, LogUserAgent, etc.) achieves zero heap allocations per
// request in steady state.
package logger
