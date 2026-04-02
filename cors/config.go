package cors

import (
	"strconv"
	"strings"

	"github.com/goceleris/celeris"
)

// Config defines the CORS middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match on c.Path()).
	// Requests matching these paths bypass CORS processing entirely.
	SkipPaths []string

	// AllowOrigins lists allowed origins. Default: ["*"].
	AllowOrigins []string

	// AllowOriginsFunc is a custom function to validate origins.
	// Called after static and wildcard origin checks.
	// Cannot be used with wildcard "*" AllowOrigins.
	AllowOriginsFunc func(origin string) bool

	// AllowOriginRequestFunc validates origins with access to the full request context.
	// Called after AllowOriginsFunc. Useful for tenant-based or header-dependent
	// origin decisions. Cannot be used with wildcard "*" AllowOrigins.
	AllowOriginRequestFunc func(c *celeris.Context, origin string) bool

	// AllowMethods lists allowed HTTP methods.
	// Default: [GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS].
	AllowMethods []string

	// AllowHeaders lists allowed request headers.
	// Default: [Origin, Content-Type, Accept, Authorization].
	AllowHeaders []string

	// ExposeHeaders lists headers the browser can access.
	ExposeHeaders []string

	// AllowCredentials indicates whether credentials are allowed.
	AllowCredentials bool

	// AllowPrivateNetwork enables the Private Network Access spec.
	// When true, preflight responses include Access-Control-Allow-Private-Network.
	AllowPrivateNetwork bool

	// MaxAge is the preflight cache duration in seconds. Default: 0 (no cache).
	MaxAge int
}

// DefaultConfig is the default CORS configuration.
var DefaultConfig = Config{
	AllowOrigins: []string{"*"},
	AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
	AllowHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization"},
}

func applyDefaults(cfg Config) Config {
	if len(cfg.AllowOrigins) == 0 {
		cfg.AllowOrigins = DefaultConfig.AllowOrigins
	}
	if len(cfg.AllowMethods) == 0 {
		cfg.AllowMethods = DefaultConfig.AllowMethods
	}
	if len(cfg.AllowHeaders) == 0 {
		cfg.AllowHeaders = DefaultConfig.AllowHeaders
	}
	return cfg
}

func (cfg Config) validate() {
	if cfg.AllowCredentials {
		for _, o := range cfg.AllowOrigins {
			if o == "*" {
				panic("cors: AllowCredentials cannot be used with wildcard AllowOrigins")
			}
		}
	}
	if cfg.AllowOriginsFunc != nil {
		for _, o := range cfg.AllowOrigins {
			if o == "*" {
				panic("cors: AllowOriginsFunc cannot be used with wildcard AllowOrigins")
			}
		}
	}
	if cfg.AllowOriginRequestFunc != nil {
		for _, o := range cfg.AllowOrigins {
			if o == "*" {
				panic("cors: AllowOriginRequestFunc cannot be used with wildcard AllowOrigins")
			}
		}
	}
}

// wildcardPattern represents a parsed wildcard origin like "https://*.example.com".
type wildcardPattern struct {
	prefix string
	suffix string
}

func (w wildcardPattern) match(origin string) bool {
	return len(origin) >= len(w.prefix)+len(w.suffix)+1 &&
		strings.HasPrefix(origin, w.prefix) &&
		strings.HasSuffix(origin, w.suffix)
}

// precomputed holds pre-joined header values for zero-alloc responses.
type precomputed struct {
	allowAllOrigins        bool
	originSet              map[string]struct{}
	wildcardPatterns       []wildcardPattern
	allowOriginsFunc       func(string) bool
	allowOriginRequestFunc func(*celeris.Context, string) bool
	allowMethods           string
	allowHeaders           string
	exposeHeaders          string
	maxAge                 string
	preflightVary          string
	allowPrivateNetwork    bool
}

func precompute(cfg Config) precomputed {
	p := precomputed{
		allowMethods:           strings.Join(cfg.AllowMethods, ", "),
		allowHeaders:           strings.Join(cfg.AllowHeaders, ", "),
		allowOriginsFunc:       cfg.AllowOriginsFunc,
		allowOriginRequestFunc: cfg.AllowOriginRequestFunc,
		allowPrivateNetwork:    cfg.AllowPrivateNetwork,
	}
	if len(cfg.ExposeHeaders) > 0 {
		p.exposeHeaders = strings.Join(cfg.ExposeHeaders, ", ")
	}
	if cfg.MaxAge > 0 {
		p.maxAge = strconv.Itoa(cfg.MaxAge)
	}

	for _, o := range cfg.AllowOrigins {
		if o == "*" {
			p.allowAllOrigins = true
			break
		}
	}

	if !p.allowAllOrigins {
		p.originSet = make(map[string]struct{})
		for _, o := range cfg.AllowOrigins {
			if strings.Contains(o, "*") {
				if strings.Count(o, "*") > 1 {
					panic("cors: origin pattern must contain at most one wildcard: " + o)
				}
				idx := strings.Index(o, "*")
				p.wildcardPatterns = append(p.wildcardPatterns, wildcardPattern{
					prefix: o[:idx],
					suffix: o[idx+1:],
				})
			} else {
				p.originSet[o] = struct{}{}
			}
		}
	}

	vary := "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
	if cfg.AllowPrivateNetwork {
		vary += ", Access-Control-Request-Private-Network"
	}
	p.preflightVary = vary

	return p
}
