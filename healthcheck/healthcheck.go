package healthcheck

import (
	"context"
	"time"

	"github.com/goceleris/celeris"
)

type probeResponse struct {
	Status string `json:"status"`
}

var (
	responseOK          = probeResponse{Status: "ok"}
	responseUnavailable = probeResponse{Status: "unavailable"}
)

// New creates a healthcheck middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	livePath := cfg.LivePath
	readyPath := cfg.ReadyPath
	startPath := cfg.StartPath

	liveChecker := cfg.LiveChecker
	readyChecker := cfg.ReadyChecker
	startChecker := cfg.StartChecker
	checkerTimeout := cfg.CheckerTimeout

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		method := c.Method()
		if method != "GET" && method != "HEAD" {
			return c.Next()
		}

		path := c.Path()

		switch path {
		case livePath:
			return respond(c, runChecker(liveChecker, c, checkerTimeout))
		case readyPath:
			return respond(c, runChecker(readyChecker, c, checkerTimeout))
		case startPath:
			return respond(c, runChecker(startChecker, c, checkerTimeout))
		default:
			return c.Next()
		}
	}
}

// runChecker runs the health checker with a context deadline so that
// well-behaved checkers (those that respect c.Context().Done()) can
// terminate early on timeout. The context is cancelled after the
// result is received or the deadline expires.
func runChecker(checker Checker, c *celeris.Context, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(c.Context(), timeout)
	defer cancel()
	c.SetContext(ctx)

	done := make(chan bool, 1)
	go func() {
		done <- checker(c)
	}()

	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		return false
	}
}

func respond(c *celeris.Context, ok bool) error {
	if ok {
		return c.JSON(200, responseOK)
	}
	return c.JSON(503, responseUnavailable)
}
