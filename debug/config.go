package debug

import (
	"net"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/observe"
)

// Config defines the debug middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// Prefix is the URL path prefix for debug endpoints.
	// Default: "/debug/celeris".
	Prefix string

	// AuthFunc is an authentication check executed before any debug endpoint.
	// If it returns false, the middleware responds with 403 Forbidden.
	// Default: allows only loopback IPs (127.0.0.1 and ::1).
	// Set to func(*celeris.Context) bool { return true } to allow public access.
	AuthFunc func(c *celeris.Context) bool

	// Server provides access to registered routes via Server.Routes().
	// Nil is safe; the /routes endpoint returns an empty list.
	Server *celeris.Server

	// Collector provides metrics via Collector.Snapshot().
	// Nil is safe; the /metrics endpoint returns 501 Not Implemented.
	Collector *observe.Collector

	// Endpoints selectively enables or disables individual debug endpoints.
	// Keys are endpoint names: "status", "metrics", "config", "routes",
	// "memory", "build". A true value enables the endpoint; false disables it.
	// When nil (default), all endpoints are enabled.
	Endpoints map[string]bool

	// MemStatsTTL controls how long the /memory endpoint caches
	// runtime.ReadMemStats results. ReadMemStats is expensive (it STWs the
	// runtime), so caching avoids hammering under load.
	// Default: 1s. Set to 0 to disable caching (not recommended).
	MemStatsTTL time.Duration
}

// DefaultConfig is the default debug middleware configuration.
var DefaultConfig = Config{
	Prefix: "/debug/celeris",
	AuthFunc: func(c *celeris.Context) bool {
		host, _, _ := net.SplitHostPort(c.RemoteAddr())
		if ip := net.ParseIP(host); ip != nil {
			return ip.IsLoopback()
		}
		return false
	},
}

func applyDefaults(cfg Config) Config {
	if cfg.Prefix == "" {
		cfg.Prefix = "/debug/celeris"
	}
	if cfg.AuthFunc == nil {
		cfg.AuthFunc = DefaultConfig.AuthFunc
	}
	if cfg.MemStatsTTL == 0 {
		cfg.MemStatsTTL = time.Second
	}
	return cfg
}

func (cfg Config) validate() {}
