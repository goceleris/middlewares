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

		var ok bool
		switch path {
		case livePath:
			ok = runChecker(liveChecker, c, checkerTimeout)
		case readyPath:
			ok = runChecker(readyChecker, c, checkerTimeout)
		case startPath:
			ok = runChecker(startChecker, c, checkerTimeout)
		default:
			return c.Next()
		}
		return respond(c, ok, method == "HEAD")
	}
}

// runChecker runs the health checker. When timeout is positive, the
// checker runs in a goroutine with a context deadline. When timeout is
// zero or negative, the checker is called synchronously without
// goroutine/channel/context overhead (fast-path for trivial checkers).
func runChecker(checker Checker, c *celeris.Context, timeout time.Duration) bool {
	if timeout <= 0 {
		return checker(c)
	}

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

func respond(c *celeris.Context, ok bool, head bool) error {
	status := 503
	if ok {
		status = 200
	}
	if head {
		return c.NoContent(status)
	}
	if ok {
		return c.JSON(status, responseOK)
	}
	return c.JSON(status, responseUnavailable)
}
