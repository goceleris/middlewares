package healthcheck

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"

	"github.com/goceleris/middlewares/internal/testutil"
)

func okHandler(c *celeris.Context) error {
	return c.String(200, "ok")
}

func TestLivenessDefault(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	var resp probeResponse
	if err := json.Unmarshal(rec.Body, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status: got %q, want %q", resp.Status, "ok")
	}
}

func TestReadinessDefault(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/readyz")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	var resp probeResponse
	if err := json.Unmarshal(rec.Body, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status: got %q, want %q", resp.Status, "ok")
	}
}

func TestStartupDefault(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/startupz")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	var resp probeResponse
	if err := json.Unmarshal(rec.Body, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status: got %q, want %q", resp.Status, "ok")
	}
}

func TestCheckerReturnsFalse(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		path string
	}{
		{"live", Config{LiveChecker: func(_ *celeris.Context) bool { return false }}, "/livez"},
		{"ready", Config{ReadyChecker: func(_ *celeris.Context) bool { return false }}, "/readyz"},
		{"start", Config{StartChecker: func(_ *celeris.Context) bool { return false }}, "/startupz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := New(tt.cfg)
			rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", tt.path)
			testutil.AssertNoError(t, err)
			testutil.AssertStatus(t, rec, 503)

			var resp probeResponse
			if err := json.Unmarshal(rec.Body, &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}
			if resp.Status != "unavailable" {
				t.Fatalf("status: got %q, want %q", resp.Status, "unavailable")
			}
		})
	}
}

func TestNonProbePath(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/api/users")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestCustomPaths(t *testing.T) {
	mw := New(Config{
		LivePath:  "/health/live",
		ReadyPath: "/health/ready",
		StartPath: "/health/startup",
	})

	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/health/live")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	rec, err = testutil.RunMiddlewareWithMethod(t, mw, "GET", "/health/ready")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	rec, err = testutil.RunMiddlewareWithMethod(t, mw, "GET", "/health/startup")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	// Original default paths should pass through.
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err = testutil.RunChain(t, chain, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestDefaultConfigPaths(t *testing.T) {
	if DefaultConfig.LivePath != "/livez" {
		t.Fatalf("DefaultConfig.LivePath: got %q, want %q", DefaultConfig.LivePath, "/livez")
	}
	if DefaultConfig.ReadyPath != "/readyz" {
		t.Fatalf("DefaultConfig.ReadyPath: got %q, want %q", DefaultConfig.ReadyPath, "/readyz")
	}
	if DefaultConfig.StartPath != "/startupz" {
		t.Fatalf("DefaultConfig.StartPath: got %q, want %q", DefaultConfig.StartPath, "/startupz")
	}
}

func TestDefaultConfigCheckers(t *testing.T) {
	if DefaultConfig.LiveChecker == nil {
		t.Fatal("DefaultConfig.LiveChecker should not be nil")
	}
	if DefaultConfig.ReadyChecker == nil {
		t.Fatal("DefaultConfig.ReadyChecker should not be nil")
	}
	if DefaultConfig.StartChecker == nil {
		t.Fatal("DefaultConfig.StartChecker should not be nil")
	}
	if !DefaultConfig.LiveChecker(nil) {
		t.Fatal("DefaultConfig.LiveChecker should return true")
	}
	if !DefaultConfig.ReadyChecker(nil) {
		t.Fatal("DefaultConfig.ReadyChecker should return true")
	}
	if !DefaultConfig.StartChecker(nil) {
		t.Fatal("DefaultConfig.StartChecker should return true")
	}
}

func TestApplyDefaultsFillsPaths(t *testing.T) {
	cfg := applyDefaults(Config{})
	if cfg.LivePath != "/livez" {
		t.Fatalf("applyDefaults LivePath: got %q, want %q", cfg.LivePath, "/livez")
	}
	if cfg.ReadyPath != "/readyz" {
		t.Fatalf("applyDefaults ReadyPath: got %q, want %q", cfg.ReadyPath, "/readyz")
	}
	if cfg.StartPath != "/startupz" {
		t.Fatalf("applyDefaults StartPath: got %q, want %q", cfg.StartPath, "/startupz")
	}
}

func TestApplyDefaultsFillsCheckers(t *testing.T) {
	cfg := applyDefaults(Config{})
	if cfg.LiveChecker == nil || cfg.ReadyChecker == nil || cfg.StartChecker == nil {
		t.Fatal("applyDefaults should fill nil checkers")
	}
}

func TestApplyDefaultsPreservesCustom(t *testing.T) {
	custom := func(_ *celeris.Context) bool { return false }
	cfg := applyDefaults(Config{
		LivePath:     "/l",
		ReadyPath:    "/r",
		StartPath:    "/s",
		LiveChecker:  custom,
		ReadyChecker: custom,
		StartChecker: custom,
	})
	if cfg.LivePath != "/l" {
		t.Fatalf("applyDefaults LivePath: got %q, want %q", cfg.LivePath, "/l")
	}
	if cfg.ReadyPath != "/r" {
		t.Fatalf("applyDefaults ReadyPath: got %q, want %q", cfg.ReadyPath, "/r")
	}
	if cfg.StartPath != "/s" {
		t.Fatalf("applyDefaults StartPath: got %q, want %q", cfg.StartPath, "/s")
	}
	if cfg.LiveChecker(nil) {
		t.Fatal("custom LiveChecker should return false")
	}
}

func TestPOSTMethodPassesThrough(t *testing.T) {
	mw := New()
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "POST", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestHEADMethodAllowed(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "HEAD", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestExportedPathConstants(t *testing.T) {
	if DefaultLivePath != "/livez" {
		t.Fatalf("DefaultLivePath: got %q, want %q", DefaultLivePath, "/livez")
	}
	if DefaultReadyPath != "/readyz" {
		t.Fatalf("DefaultReadyPath: got %q, want %q", DefaultReadyPath, "/readyz")
	}
	if DefaultStartPath != "/startupz" {
		t.Fatalf("DefaultStartPath: got %q, want %q", DefaultStartPath, "/startupz")
	}
}

func FuzzHealthcheckPaths(f *testing.F) {
	f.Add("/livez")
	f.Add("/readyz")
	f.Add("/startupz")
	f.Add("/api/users")
	f.Add("")
	f.Add("/")
	f.Add("/livez/extra")
	f.Fuzz(func(t *testing.T, path string) {
		mw := New()
		ctx, _ := celeristest.NewContextT(t, "GET", path)
		_ = mw(ctx)
	})
}

func TestContentTypeJSON(t *testing.T) {
	mw := New()
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertHeaderContains(t, rec, "content-type", "application/json")
}

func TestCheckerReceivesContext(t *testing.T) {
	var received bool
	mw := New(Config{
		LiveChecker: func(c *celeris.Context) bool {
			received = c != nil
			return true
		},
	})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	if !received {
		t.Fatal("expected checker to receive non-nil context")
	}
}

func TestSkipBypassesHealthcheck(t *testing.T) {
	mw := New(Config{
		Skip: func(_ *celeris.Context) bool { return true },
	})
	chain := []celeris.HandlerFunc{mw, okHandler}
	rec, err := testutil.RunChain(t, chain, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
	testutil.AssertBodyContains(t, rec, "ok")
}

func TestSkipFalseStillMatchesProbe(t *testing.T) {
	mw := New(Config{
		Skip: func(_ *celeris.Context) bool { return false },
	})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)

	var resp probeResponse
	if err := json.Unmarshal(rec.Body, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status: got %q, want %q", resp.Status, "ok")
	}
}

func TestCheckerTimeoutDefault(t *testing.T) {
	cfg := applyDefaults(Config{})
	if cfg.CheckerTimeout != 5*time.Second {
		t.Fatalf("default CheckerTimeout: got %v, want 5s", cfg.CheckerTimeout)
	}
}

func TestCheckerTimeoutExceeded(t *testing.T) {
	mw := New(Config{
		CheckerTimeout: 10 * time.Millisecond,
		LiveChecker: func(_ *celeris.Context) bool {
			time.Sleep(100 * time.Millisecond)
			return true
		},
	})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 503)

	var resp probeResponse
	if err := json.Unmarshal(rec.Body, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Status != "unavailable" {
		t.Fatalf("status: got %q, want %q", resp.Status, "unavailable")
	}
}

func TestCheckerCompletesWithinTimeout(t *testing.T) {
	mw := New(Config{
		CheckerTimeout: 1 * time.Second,
		LiveChecker: func(_ *celeris.Context) bool {
			return true
		},
	})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 200)
}

func TestCheckerTimeoutAppliedToReady(t *testing.T) {
	mw := New(Config{
		CheckerTimeout: 10 * time.Millisecond,
		ReadyChecker: func(_ *celeris.Context) bool {
			time.Sleep(100 * time.Millisecond)
			return true
		},
	})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/readyz")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 503)
}

func TestCheckerTimeoutCustomValue(t *testing.T) {
	cfg := applyDefaults(Config{CheckerTimeout: 10 * time.Second})
	if cfg.CheckerTimeout != 10*time.Second {
		t.Fatalf("custom CheckerTimeout: got %v, want 10s", cfg.CheckerTimeout)
	}
}

func TestCheckerContextCancellation(t *testing.T) {
	ctxDone := make(chan struct{})
	mw := New(Config{
		CheckerTimeout: 50 * time.Millisecond,
		LiveChecker: func(c *celeris.Context) bool {
			// Capture the context immediately to avoid racing with
			// context reset after the middleware returns.
			ctx := c.Context()
			<-ctx.Done()
			close(ctxDone)
			return false
		},
	})
	rec, err := testutil.RunMiddlewareWithMethod(t, mw, "GET", "/livez")
	testutil.AssertNoError(t, err)
	testutil.AssertStatus(t, rec, 503)

	select {
	case <-ctxDone:
		// Checker observed context cancellation.
	case <-time.After(2 * time.Second):
		t.Fatal("expected checker to observe context cancellation")
	}
}
