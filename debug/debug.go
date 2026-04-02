package debug

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/observe"
)

type memStatsCache struct {
	mu       sync.Mutex
	data     memoryResponse
	cachedAt time.Time
	ttl      time.Duration
}

type statusResponse struct {
	Uptime    string `json:"uptime"`
	GoVersion string `json:"go_version"`
}

type memoryResponse struct {
	Alloc      uint64  `json:"alloc"`
	TotalAlloc uint64  `json:"total_alloc"`
	Sys        uint64  `json:"sys"`
	HeapInuse  uint64  `json:"heap_inuse"`
	HeapIdle   uint64  `json:"heap_idle"`
	NumGC      uint32  `json:"num_gc"`
	GCCPUFrac  float64 `json:"gc_cpu_fraction"`
}

type buildResponse struct {
	Module    string            `json:"module"`
	GoVersion string            `json:"go_version"`
	VCS       map[string]string `json:"vcs,omitempty"`
}

type runtimeResponse struct {
	Goroutines int `json:"goroutines"`
	NumCPU     int `json:"num_cpu"`
	GOMAXPROCS int `json:"gomaxprocs"`
}

// allEndpoints is the canonical list of endpoint names.
var allEndpoints = [...]string{"status", "metrics", "config", "routes", "memory", "build", "runtime"}

func isEndpointEnabled(endpoints map[string]bool, name string) bool {
	if endpoints == nil {
		return true
	}
	enabled, ok := endpoints[name]
	return ok && enabled
}

// New creates a debug middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	prefix := strings.TrimRight(cfg.Prefix, "/")
	prefixSlash := prefix + "/"
	startTime := time.Now()

	statusPath := prefix + "/status"
	metricsPath := prefix + "/metrics"
	configPath := prefix + "/config"
	routesPath := prefix + "/routes"
	memoryPath := prefix + "/memory"
	buildPath := prefix + "/build"
	runtimePath := prefix + "/runtime"

	endpoints := cfg.Endpoints
	msCache := &memStatsCache{ttl: cfg.MemStatsTTL}

	// Pre-build the index listing of available endpoints.
	available := make([]string, 0, len(allEndpoints))
	for _, name := range allEndpoints {
		if isEndpointEnabled(endpoints, name) {
			available = append(available, prefixSlash+name)
		}
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		path := c.Path()

		if path == prefix || path == prefix+"/" {
			if cfg.AuthFunc != nil && !cfg.AuthFunc(c) {
				return c.NoContent(403)
			}
			return c.JSON(200, available)
		}

		if !strings.HasPrefix(path, prefixSlash) {
			return c.Next()
		}

		if cfg.AuthFunc != nil && !cfg.AuthFunc(c) {
			return c.NoContent(403)
		}

		switch path {
		case statusPath:
			if !isEndpointEnabled(endpoints, "status") {
				return c.NoContent(404)
			}
			return handleStatus(c, startTime)
		case metricsPath:
			if !isEndpointEnabled(endpoints, "metrics") {
				return c.NoContent(404)
			}
			return handleMetrics(c, cfg.Collector)
		case configPath:
			if !isEndpointEnabled(endpoints, "config") {
				return c.NoContent(404)
			}
			return handleConfig(c)
		case routesPath:
			if !isEndpointEnabled(endpoints, "routes") {
				return c.NoContent(404)
			}
			return handleRoutes(c, cfg.Server)
		case memoryPath:
			if !isEndpointEnabled(endpoints, "memory") {
				return c.NoContent(404)
			}
			return handleMemory(c, msCache)
		case buildPath:
			if !isEndpointEnabled(endpoints, "build") {
				return c.NoContent(404)
			}
			return handleBuild(c)
		case runtimePath:
			if !isEndpointEnabled(endpoints, "runtime") {
				return c.NoContent(404)
			}
			return handleRuntime(c)
		default:
			return c.NoContent(404)
		}
	}
}

func handleStatus(c *celeris.Context, startTime time.Time) error {
	return c.JSON(200, statusResponse{
		Uptime:    time.Since(startTime).String(),
		GoVersion: runtime.Version(),
	})
}

func handleMetrics(c *celeris.Context, collector *observe.Collector) error {
	if collector == nil {
		return c.NoContent(501)
	}
	return c.JSON(200, collector.Snapshot())
}

type configResponse struct {
	GoVersion  string `json:"go_version"`
	GoOS       string `json:"go_os"`
	GoArch     string `json:"go_arch"`
	NumCPU     int    `json:"num_cpu"`
	Goroutines int    `json:"goroutines"`
}

var cachedConfig = configResponse{
	GoVersion: runtime.Version(),
	GoOS:      runtime.GOOS,
	GoArch:    runtime.GOARCH,
	NumCPU:    runtime.NumCPU(),
}

func handleConfig(c *celeris.Context) error {
	resp := cachedConfig
	resp.Goroutines = runtime.NumGoroutine()
	return c.JSON(200, resp)
}

func handleRoutes(c *celeris.Context, server *celeris.Server) error {
	if server == nil {
		return c.JSON(200, []any{})
	}
	return c.JSON(200, server.Routes())
}

func handleMemory(c *celeris.Context, cache *memStatsCache) error {
	cache.mu.Lock()
	if cache.ttl > 0 && time.Since(cache.cachedAt) < cache.ttl {
		resp := cache.data
		cache.mu.Unlock()
		return c.JSON(200, resp)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	resp := memoryResponse{
		Alloc:      m.Alloc,
		TotalAlloc: m.TotalAlloc,
		Sys:        m.Sys,
		HeapInuse:  m.HeapInuse,
		HeapIdle:   m.HeapIdle,
		NumGC:      m.NumGC,
		GCCPUFrac:  m.GCCPUFraction,
	}
	cache.data = resp
	cache.cachedAt = time.Now()
	cache.mu.Unlock()
	return c.JSON(200, resp)
}

func handleRuntime(c *celeris.Context) error {
	return c.JSON(200, runtimeResponse{
		Goroutines: runtime.NumGoroutine(),
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	})
}

func handleBuild(c *celeris.Context) error {
	resp := buildResponse{
		GoVersion: runtime.Version(),
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		resp.Module = info.Main.Path
		vcs := make(map[string]string)
		for _, s := range info.Settings {
			if strings.HasPrefix(s.Key, "vcs.") {
				vcs[s.Key] = s.Value
			}
		}
		if len(vcs) > 0 {
			resp.VCS = vcs
		}
	}
	return c.JSON(200, resp)
}
