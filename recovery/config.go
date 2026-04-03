package recovery

import (
	"errors"
	"log/slog"

	"github.com/goceleris/celeris"
)

// ErrBrokenPipe is returned when a panic is caused by a broken pipe or
// connection reset and no BrokenPipeHandler is configured. Callers can
// use errors.Is to detect this case.
var ErrBrokenPipe = errors.New("recovery: broken pipe (client disconnected)")

// Config defines the recovery middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// ErrorHandler handles the recovered panic value. Default: JSON 500 response.
	ErrorHandler func(c *celeris.Context, err any) error

	// BrokenPipeHandler handles broken pipe / connection reset panics.
	// When nil, broken pipe panics are logged at WARN level without a stack
	// trace and the middleware returns ErrBrokenPipe.
	BrokenPipeHandler func(c *celeris.Context, err any) error

	// StackSize is the max bytes for stack trace capture. Default: 4096.
	// Set to 0 to disable stack capture (panic value, method, and path
	// are still logged). Negative values are rejected by validate().
	StackSize int

	// DisableLogStack disables stack trace logging on panic recovery.
	// Default: false (stacks are logged). This replaces the old LogStack
	// field, fixing the zero-value problem where an unset bool defaulted
	// to "no logging" instead of "logging enabled".
	DisableLogStack bool

	// LogStack is deprecated: use DisableLogStack instead. Due to the
	// zero-value problem, only LogStack: true has effect (it forces
	// DisableLogStack to false). LogStack: false is indistinguishable
	// from "not set" and is ignored. To suppress stack logging, use
	// DisableLogStack: true.
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

// defaultStackSize is the default stack trace capture size in bytes.
const defaultStackSize = 4096

// defaultConfig returns a fresh copy of the default recovery configuration.
func defaultConfig() Config {
	return Config{
		StackSize: defaultStackSize,
	}
}

func applyDefaults(cfg Config) Config {
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}
	if cfg.StackSize < 0 {
		cfg.StackSize = defaultStackSize
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

func (cfg Config) validate() {
	if cfg.StackSize < 0 {
		panic("recovery: StackSize must be >= 0")
	}
}
