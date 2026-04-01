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
	// To disable stack capture, set LogStack to false.
	StackSize int

	// LogStack controls whether the stack trace is logged. Default: true.
	LogStack bool

	// StackAll captures all goroutine stacks, not just the current one.
	// Default: false (current goroutine only).
	StackAll bool

	// Logger is the slog logger for panic logging. Default: slog.Default().
	Logger *slog.Logger
}

// DefaultConfig is the default recovery configuration.
var DefaultConfig = Config{
	StackSize: 4096,
	LogStack:  true,
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
	return cfg
}

var defaultErrorBody = []byte(`{"error":"Internal Server Error"}`)

func defaultErrorHandler(c *celeris.Context, _ any) error {
	return c.Blob(500, "application/json", defaultErrorBody)
}

func (cfg Config) validate() {}
