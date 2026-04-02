package cors

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/goceleris/celeris"
)

// maxOriginLength is the maximum allowed length for an Origin header value.
// Origins exceeding this are rejected before any comparison to prevent
// CPU waste on extremely long strings.
const maxOriginLength = 256

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
	//
	// The middleware validates that the incoming Origin header looks like a
	// serialized origin (has scheme + host, no path/query/fragment/userinfo)
	// before passing it to this function. Malformed origins are rejected.
	AllowOriginsFunc func(origin string) bool

	// AllowOriginRequestFunc validates origins with access to the full request context.
	// Called after AllowOriginsFunc. Useful for tenant-based or header-dependent
	// origin decisions. Cannot be used with wildcard "*" AllowOrigins.
	//
	// The same serialized-origin validation applies as for AllowOriginsFunc.
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

	// DisableValueRedaction, when false (default), replaces origin values
	// in panic messages with "[redacted]" to prevent leaking potentially
	// sensitive origin information in logs.
	DisableValueRedaction bool

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

// redactOrigin returns "[redacted]" unless DisableValueRedaction is true.
func (cfg Config) redactOrigin(origin string) string {
	if cfg.DisableValueRedaction {
		return origin
	}
	return "[redacted]"
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
	nullAllowed            bool
	validateOriginFunc     bool
	originSet              map[string]struct{}
	wildcardPatterns       []wildcardPattern
	allowOriginsFunc       func(string) bool
	allowOriginRequestFunc func(*celeris.Context, string) bool
	allowMethods           string
	allowHeaders           string
	mirrorRequestHeaders   bool
	exposeHeaders          string
	maxAge                 string
	preflightVary          string
	allowPrivateNetwork    bool
}

func precompute(cfg Config) precomputed {
	p := precomputed{
		allowMethods:           strings.Join(cfg.AllowMethods, ", "),
		allowOriginsFunc:       cfg.AllowOriginsFunc,
		allowOriginRequestFunc: cfg.AllowOriginRequestFunc,
		allowPrivateNetwork:    cfg.AllowPrivateNetwork,
		validateOriginFunc:     cfg.AllowOriginsFunc != nil || cfg.AllowOriginRequestFunc != nil,
	}

	// Mirror request headers when AllowHeaders is not configured.
	if len(cfg.AllowHeaders) == 0 {
		p.mirrorRequestHeaders = true
	} else {
		p.allowHeaders = strings.Join(cfg.AllowHeaders, ", ")
	}

	if len(cfg.ExposeHeaders) > 0 {
		p.exposeHeaders = strings.Join(cfg.ExposeHeaders, ", ")
	}
	if cfg.MaxAge < 0 {
		p.maxAge = "0"
	} else if cfg.MaxAge > 0 {
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
			if o == "null" {
				p.nullAllowed = true
				continue
			}
			if strings.Contains(o, "*") {
				if strings.Count(o, "*") > 1 {
					panic("cors: origin pattern must contain at most one wildcard: " + cfg.redactOrigin(o))
				}
				norm := normalizeOrigin(o)
				idx := strings.Index(norm, "*")
				p.wildcardPatterns = append(p.wildcardPatterns, wildcardPattern{
					prefix: norm[:idx],
					suffix: norm[idx+1:],
				})
			} else {
				p.originSet[normalizeOrigin(o)] = struct{}{}
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

// isSerializedOrigin checks whether an origin string looks like a valid
// serialized origin per RFC 6454: scheme "://" host [ ":" port ].
// Returns false for origins with path, query, fragment, or userinfo.
func isSerializedOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return true
}

// normalizeOrigin lowercases the scheme and host of a URL-shaped origin.
// Plain values (e.g. "*") are returned unchanged.
func normalizeOrigin(raw string) string {
	if !strings.Contains(raw, "://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}
