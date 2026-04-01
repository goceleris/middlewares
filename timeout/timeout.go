package timeout

import (
	"context"

	"github.com/goceleris/celeris"
)

// New creates a timeout middleware with the given config.
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

	timeout := cfg.Timeout
	handler := cfg.ErrorHandler

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		childCtx, cancel := context.WithTimeout(c.Context(), timeout)
		defer cancel()

		c.SetContext(childCtx)
		err := c.Next()

		if childCtx.Err() == context.DeadlineExceeded {
			return handler(c)
		}

		return err
	}
}
