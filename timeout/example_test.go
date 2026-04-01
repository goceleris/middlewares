package timeout_test

import (
	"time"

	"github.com/goceleris/middlewares/timeout"
)

func ExampleNew() {
	// Zero-config: 5-second cooperative timeout.
	_ = timeout.New()
}

func ExampleNew_preemptive() {
	// Preemptive timeout: returns 503 even if handler is blocked.
	// Handlers MUST check c.Context().Done() for prompt cancellation.
	_ = timeout.New(timeout.Config{
		Timeout:    3 * time.Second,
		Preemptive: true,
	})
}
