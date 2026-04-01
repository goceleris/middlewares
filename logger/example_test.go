package logger_test

import (
	"io"
	"log/slog"
	"os"

	"github.com/goceleris/middlewares/logger"
)

func ExampleNew() {
	// Zero-config: logs to slog.Default() with INFO/WARN/ERROR levels.
	_ = logger.New()
}

func ExampleNew_fastHandler() {
	// FastHandler: zero-allocation structured logging with color output.
	log := slog.New(logger.NewFastHandler(os.Stderr, &logger.FastHandlerOptions{
		Color: true,
	}))
	_ = logger.New(logger.Config{Output: log})
}

func ExampleNew_customFields() {
	// Discard output for example; add custom fields to every log entry.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	_ = logger.New(logger.Config{
		Output:    log,
		SkipPaths: []string{"/health", "/ready"},
	})
}
