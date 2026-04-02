package recovery

import (
	"log/slog"

	"github.com/goceleris/celeris"
)

// Config defines the recovery middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// ErrorHandler handles the recovered panic value. Default: JSON 500 response.
	ErrorHandler func(c *celeris.Context, err any) error

	// BrokenPipeHandler handles broken pipe / connection reset panics.
	// When nil, broken pipe panics are logged at WARN level without a stack trace
	// and the middleware returns nil (client is disconnected).
	BrokenPipeHandler func(c *celeris.Context, err any) error

	// StackSize is the max bytes for stack trace capture. Default: 4096.
	// To disable stack capture, set DisableLogStack to true.
	StackSize int

	// DisableLogStack disables stack trace logging on panic recovery.
	// Default: false (stacks are logged). This replaces the old LogStack
	// field, fixing the zero-value problem where an unset bool defaulted
	// to "no logging" instead of "logging enabled".
	DisableLogStack bool

	// LogStack is deprecated: use DisableLogStack instead. When set to
	// true explicitly, it overrides DisableLogStack to false (stacks are
	// logged). When set to false explicitly, it sets DisableLogStack to
	// true (stacks are suppressed). In new code, use DisableLogStack only.
	//
	// Deprecated: Use DisableLogStack.
	LogStack bool

	// StackAll captures all goroutine stacks, not just the current one.
	// Default: false (current goroutine only).
	StackAll bool

	// DisableBrokenPipeLog suppresses the WARN-level log for broken pipe
	// and ECONNRESET panics. Default: false (log enabled).
	DisableBrokenPipeLog bool

	// Logger is the slog logger for panic logging. Default: slog.Default().
	Logger *slog.Logger
}

// DefaultConfig is the default recovery configuration.
var DefaultConfig = Config{
	StackSize: 4096,
}

func applyDefaults(cfg Config) Config {
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}
	if cfg.StackSize <= 0 {
		cfg.StackSize = DefaultConfig.StackSize
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// Backward compatibility: LogStack (deprecated) overrides DisableLogStack.
	if cfg.LogStack {
		cfg.DisableLogStack = false
	}
	return cfg
}

var defaultErrorBody = []byte(`{"error":"Internal Server Error"}`)

func defaultErrorHandler(c *celeris.Context, _ any) error {
	return c.Blob(500, "application/json", defaultErrorBody)
}

func (cfg Config) validate() {}
