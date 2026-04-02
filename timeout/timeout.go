package timeout

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

var chanPool = sync.Pool{New: func() any { return make(chan error, 1) }}

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
	timeoutFunc := cfg.TimeoutFunc
	errHandler := cfg.ErrorHandler
	preemptive := cfg.Preemptive
	timeoutErrors := cfg.TimeoutErrors

	if preemptive {
		return preemptiveHandler(skipMap, dur, timeoutFunc, errHandler, cfg.Skip, timeoutErrors)
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		d := dur
		if timeoutFunc != nil {
			if td := timeoutFunc(c); td > 0 {
				d = td
			}
		}

		childCtx, cancel := context.WithTimeout(c.Context(), d)
		defer cancel()

		c.SetContext(childCtx)
		err := c.Next()

		if childCtx.Err() == context.DeadlineExceeded {
			return errHandler(c)
		}

		if err != nil && isTimeoutError(err, timeoutErrors) {
			return errHandler(c)
		}

		return err
	}
}

// isTimeoutError checks if err matches any of the configured timeout-like errors.
func isTimeoutError(err error, timeoutErrors []error) bool {
	for _, te := range timeoutErrors {
		if errors.Is(err, te) {
			return true
		}
	}
	return false
}

func preemptiveHandler(
	skipMap map[string]struct{},
	dur time.Duration,
	timeoutFunc func(*celeris.Context) time.Duration,
	errHandler func(*celeris.Context) error,
	skip func(*celeris.Context) bool,
	timeoutErrors []error,
) celeris.HandlerFunc {
	return func(c *celeris.Context) error {
		if skip != nil && skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		d := dur
		if timeoutFunc != nil {
			if td := timeoutFunc(c); td > 0 {
				d = td
			}
		}

		childCtx, cancel := context.WithTimeout(c.Context(), d)
		defer cancel()

		c.SetContext(childCtx)
		c.BufferResponse()

		done := chanPool.Get().(chan error)
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
			chanPool.Put(done)
			if err != nil && isTimeoutError(err, timeoutErrors) {
				return errHandler(c)
			}
			if flushErr := c.FlushResponse(); flushErr != nil {
				return flushErr
			}
			return err
		case <-childCtx.Done():
			// Wait for the handler goroutine to finish so it no longer
			// touches the Context before we return (prevents data race
			// with Context pool reclamation).
			<-done
			chanPool.Put(done)
			return errHandler(c)
		}
	}
}
