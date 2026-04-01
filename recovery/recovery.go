package recovery

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/goceleris/celeris"
)

var stackPool = sync.Pool{New: func() any {
	buf := make([]byte, 4096)
	return &buf
}}

// New creates a recovery middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	handler := cfg.ErrorHandler
	stackSize := cfg.StackSize
	logStack := cfg.LogStack
	log := cfg.Logger

	return func(c *celeris.Context) (retErr error) {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		defer func() {
			if r := recover(); r != nil {
				if logStack && stackSize > 0 {
					bufPtr := stackPool.Get().(*[]byte)
					buf := *bufPtr
					if len(buf) < stackSize {
						buf = make([]byte, stackSize)
					}
					n := runtime.Stack(buf[:stackSize], false)
					log.LogAttrs(c.Context(), slog.LevelError, "panic recovered",
						slog.String("error", fmt.Sprint(r)),
						slog.String("stack", string(buf[:n])),
					)
					*bufPtr = buf
					stackPool.Put(bufPtr)
				} else if logStack {
					log.LogAttrs(c.Context(), slog.LevelError, "panic recovered",
						slog.String("error", fmt.Sprint(r)),
					)
				}
				retErr = handler(c, r)
			}
		}()

		return c.Next()
	}
}
