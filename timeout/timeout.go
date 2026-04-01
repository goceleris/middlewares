package timeout

import (
	"context"
	"time"

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

	dur := cfg.Timeout
	errHandler := cfg.ErrorHandler
	preemptive := cfg.Preemptive

	if preemptive {
		return preemptiveHandler(skipMap, dur, errHandler, cfg.Skip)
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		childCtx, cancel := context.WithTimeout(c.Context(), dur)
		defer cancel()

		c.SetContext(childCtx)
		err := c.Next()

		if childCtx.Err() == context.DeadlineExceeded {
			return errHandler(c)
		}

		return err
	}
}

func preemptiveHandler(
	skipMap map[string]struct{},
	dur time.Duration,
	errHandler func(*celeris.Context) error,
	skip func(*celeris.Context) bool,
) celeris.HandlerFunc {
	return func(c *celeris.Context) error {
		if skip != nil && skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		childCtx, cancel := context.WithTimeout(c.Context(), dur)
		defer cancel()

		c.SetContext(childCtx)
		c.BufferResponse()

		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- celeris.NewHTTPError(500, "Internal Server Error")
				}
			}()
			done <- c.Next()
		}()

		select {
		case err := <-done:
			if flushErr := c.FlushResponse(); flushErr != nil {
				return flushErr
			}
			return err
		case <-childCtx.Done():
			// Wait for the handler goroutine to finish so it no longer
			// touches the Context before we return (prevents data race
			// with Context pool reclamation).
			<-done
			return errHandler(c)
		}
	}
}
