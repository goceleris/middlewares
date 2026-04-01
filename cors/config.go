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

	// AllowOrigins lists allowed origins. Default: ["*"].
	AllowOrigins []string

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
}

// precomputed holds pre-joined header values for zero-alloc responses.
type precomputed struct {
	allowAllOrigins bool
	originSet       map[string]struct{}
	allowMethods    string
	allowHeaders    string
	exposeHeaders   string
	maxAge          string
}

func precompute(cfg Config) precomputed {
	p := precomputed{
		allowMethods: strings.Join(cfg.AllowMethods, ", "),
		allowHeaders: strings.Join(cfg.AllowHeaders, ", "),
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
		p.originSet = make(map[string]struct{}, len(cfg.AllowOrigins))
		for _, o := range cfg.AllowOrigins {
			p.originSet[o] = struct{}{}
		}
	}
	return p
}
