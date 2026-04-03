package timeout

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

var chanPool = sync.Pool{New: func() any { return make(chan error, 1) }}

// New creates a timeout middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := defaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)

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

		origCtx := c.Context()
		c.SetContext(childCtx)
		defer c.SetContext(origCtx)

		err := c.Next()

		if childCtx.Err() == context.DeadlineExceeded {
			if c.IsWritten() {
				return ErrServiceUnavailable
			}
			return errHandler(c)
		}

		if err != nil && isTimeoutError(err, timeoutErrors) {
			if c.IsWritten() {
				return ErrServiceUnavailable
			}
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

// flushOrReturn handles the error handler result in preemptive mode.
// If the error handler wrote a buffered response (returned nil), flush it.
// If it returned an error, propagate the error without flushing.
func flushOrReturn(c *celeris.Context, err error) error {
	if err != nil {
		return err
	}
	return c.FlushResponse()
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
		// Drain any stale value left from a previous pool cycle.
		select {
		case <-done:
		default:
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- celeris.NewHTTPError(500, fmt.Sprintf("panic: %v", r))
				}
			}()
			done <- c.Next()
		}()

		select {
		case err := <-done:
			chanPool.Put(done)
			if err != nil && isTimeoutError(err, timeoutErrors) {
				return flushOrReturn(c, errHandler(c))
			}
			if flushErr := c.FlushResponse(); flushErr != nil {
				return flushErr
			}
			return err
		case <-childCtx.Done():
			// Between childCtx.Done() firing and <-done completing, the
			// handler goroutine may still be touching c (writing buffered
			// response data, setting headers, etc.). The <-done receive
			// serializes: once it returns, the goroutine has exited and
			// the Context is safe to use exclusively from this goroutine.
			<-done
			chanPool.Put(done)
			// The handler may have buffered a stale response. We do NOT
			// need to explicitly discard it: errHandler's response methods
			// (JSON, String, etc.) overwrite the captured fields while
			// bufferDepth > 0, replacing the stale data. flushOrReturn
			// then flushes the errHandler's response (or propagates its
			// error without flushing).
			return flushOrReturn(c, errHandler(c))
		}
	}
}
