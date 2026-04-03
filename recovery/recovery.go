package recovery

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync"
	"syscall"

	"github.com/goceleris/celeris"
)

var stackPool = sync.Pool{New: func() any {
	buf := make([]byte, 4096)
	return &buf
}}

// New creates a recovery middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := defaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg.validate()
	cfg = applyDefaults(cfg)

	handler := cfg.ErrorHandler
	brokenPipeHandler := cfg.BrokenPipeHandler
	stackSize := cfg.StackSize
	logStack := !cfg.DisableLogStack
	stackAll := cfg.StackAll
	disableBrokenPipeLog := cfg.DisableBrokenPipeLog
	log := cfg.Logger

	return func(c *celeris.Context) (retErr error) {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(r)
				}

				if isBrokenPipe(r) {
					if !disableBrokenPipeLog {
						log.LogAttrs(c.Context(), slog.LevelWarn, "broken pipe",
							slog.String("method", c.Method()),
							slog.String("path", c.Path()),
							slog.String("error", fmt.Sprint(r)),
						)
					}
					if brokenPipeHandler != nil {
						retErr = brokenPipeHandler(c, r)
					} else {
						retErr = ErrBrokenPipe
					}
					return
				}

				if logStack && stackSize > 0 {
					bufPtr := stackPool.Get().(*[]byte)
					buf := *bufPtr
					// Discard oversized pooled buffers to bound memory.
					if cap(buf) > 2*stackSize {
						buf = make([]byte, stackSize)
					} else if len(buf) < stackSize {
						buf = make([]byte, stackSize)
					}
					n := runtime.Stack(buf[:stackSize], stackAll)
					log.LogAttrs(c.Context(), slog.LevelError, "panic recovered",
						slog.String("method", c.Method()),
						slog.String("path", c.Path()),
						slog.String("error", fmt.Sprint(r)),
						slog.String("stack", string(buf[:n])),
					)
					*bufPtr = buf
					stackPool.Put(bufPtr)
				} else if logStack {
					log.LogAttrs(c.Context(), slog.LevelError, "panic recovered",
						slog.String("method", c.Method()),
						slog.String("path", c.Path()),
						slog.String("error", fmt.Sprint(r)),
					)
				}

				// Guard: if context cancelled (client disconnected), skip writing.
				if c.Context().Err() != nil {
					log.LogAttrs(c.Context(), slog.LevelWarn, "panic after context cancelled",
						slog.String("method", c.Method()),
						slog.String("path", c.Path()),
						slog.String("error", fmt.Sprint(r)),
					)
					retErr = fmt.Errorf("recovery: panic: %v", r)
					return
				}

				// Guard: if response already committed, skip writing.
				if c.IsWritten() {
					log.LogAttrs(c.Context(), slog.LevelError, "panic after response committed",
						slog.String("method", c.Method()),
						slog.String("path", c.Path()),
						slog.String("error", fmt.Sprint(r)),
					)
					retErr = fmt.Errorf("recovery: panic after response committed: %v", r)
					return
				}

				func() {
					defer func() {
						if r2 := recover(); r2 != nil {
							log.LogAttrs(c.Context(), slog.LevelError, "panic in error handler",
								slog.String("method", c.Method()),
								slog.String("path", c.Path()),
								slog.String("error", fmt.Sprint(r2)),
							)
							retErr = defaultErrorHandler(c, r2)
						}
					}()
					retErr = handler(c, r)
				}()
			}
		}()

		return c.Next()
	}
}

func isBrokenPipe(v any) bool {
	err, ok := v.(error)
	if !ok {
		return false
	}
	// Check directly without requiring a net.OpError wrapper.
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.EPIPE) || errors.Is(opErr.Err, syscall.ECONNRESET)
	}
	return false
}
