package csrf

import (
	"strings"
	"time"

	"github.com/goceleris/celeris"
)

// Config defines the CSRF middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// TokenLength is the number of random bytes used to generate the token.
	// The resulting hex-encoded token string is twice this length.
	// Default: 32.
	TokenLength int

	// TokenLookup defines the source(s) for extracting the CSRF token on
	// unsafe methods. Format is "source:name" where source is "header",
	// "form", or "query". Multiple sources can be comma-separated; the
	// first non-empty match is used. Default: "header:X-CSRF-Token".
	TokenLookup string

	// CookieName is the name of the CSRF cookie. Default: "_csrf".
	CookieName string

	// CookiePath is the path attribute of the CSRF cookie. Default: "/".
	CookiePath string

	// CookieDomain is the domain attribute of the CSRF cookie.
	CookieDomain string

	// CookieMaxAge is the max-age of the CSRF cookie in seconds.
	// Default: 86400 (24 hours).
	CookieMaxAge int

	// CookieSecure flags the cookie for HTTPS-only transmission.
	CookieSecure bool

	// CookieHTTPOnly prevents client-side scripts from accessing the cookie.
	// Default: true. To disable, set DisableCookieHTTPOnly to true.
	CookieHTTPOnly bool

	// DisableCookieHTTPOnly explicitly disables the HTTPOnly flag on the
	// CSRF cookie. This is needed for SPA usage where client-side JavaScript
	// must read the cookie. When true, CookieHTTPOnly is forced to false.
	DisableCookieHTTPOnly bool

	// CookieSessionOnly, when true, omits MaxAge from the cookie so it
	// becomes a browser-session-scoped cookie (deleted when the browser closes).
	CookieSessionOnly bool

	// CookieSameSite controls the SameSite attribute of the CSRF cookie.
	// Default: celeris.SameSiteLaxMode.
	CookieSameSite celeris.SameSite

	// ErrorHandler handles CSRF validation failures. When nil, the
	// middleware returns the error directly (ErrMissingToken or ErrForbidden).
	ErrorHandler func(c *celeris.Context, err error) error

	// SafeMethods lists HTTP methods that do not require token validation.
	// Default: ["GET", "HEAD", "OPTIONS", "TRACE"].
	SafeMethods []string

	// TrustedOrigins lists additional origins that are allowed for
	// cross-origin requests. Each entry should be a full origin
	// (e.g. "https://app.example.com") or a wildcard subdomain pattern
	// (e.g. "https://*.example.com"). When the Origin header is present
	// on unsafe methods, it must match the request Host or one of these
	// entries. An empty list means only same-origin requests are allowed.
	TrustedOrigins []string

	// Storage enables server-side token storage (signed double-submit).
	// When set, tokens are stored in the backend and validated against
	// the store on unsafe methods. When nil, pure double-submit cookie
	// mode is used.
	Storage Storage

	// Expiration is the token lifetime in server-side storage.
	// Only used when Storage is set. Default: 1 hour.
	Expiration time.Duration

	// SingleUseToken, when true and Storage is set, deletes the token
	// from storage after successful validation. A new token is generated
	// on the next safe-method request.
	SingleUseToken bool

	// KeyGenerator provides a custom token generation function.
	// When nil, the default buffered hex generator is used.
	KeyGenerator func() string

	// ContextKey is the key used to store the CSRF token in the
	// request context. Default: "csrf_token".
	ContextKey string
}

// DefaultConfig is the default CSRF configuration.
var DefaultConfig = Config{
	TokenLength:    32,
	TokenLookup:    "header:X-CSRF-Token",
	CookieName:     "_csrf",
	CookiePath:     "/",
	CookieMaxAge:   86400,
	CookieHTTPOnly: true,
	CookieSameSite: celeris.SameSiteLaxMode,
	SafeMethods:    []string{"GET", "HEAD", "OPTIONS", "TRACE"},
	Expiration:     time.Hour,
	ContextKey:     "csrf_token",
}

func applyDefaults(cfg Config) Config {
	if cfg.TokenLength <= 0 {
		cfg.TokenLength = DefaultConfig.TokenLength
	}
	if cfg.TokenLookup == "" {
		cfg.TokenLookup = DefaultConfig.TokenLookup
	}
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultConfig.CookieName
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = DefaultConfig.CookiePath
	}
	if cfg.CookieMaxAge == 0 {
		cfg.CookieMaxAge = DefaultConfig.CookieMaxAge
	}
	if cfg.CookieSameSite == 0 {
		cfg.CookieSameSite = DefaultConfig.CookieSameSite
	}
	if len(cfg.SafeMethods) == 0 {
		cfg.SafeMethods = DefaultConfig.SafeMethods
	}
	if !cfg.CookieHTTPOnly && !cfg.DisableCookieHTTPOnly {
		cfg.CookieHTTPOnly = DefaultConfig.CookieHTTPOnly
	}
	if cfg.DisableCookieHTTPOnly {
		cfg.CookieHTTPOnly = false
	}
	if cfg.Expiration <= 0 {
		cfg.Expiration = DefaultConfig.Expiration
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = DefaultConfig.ContextKey
	}
	return cfg
}

// wildcardOrigin represents a parsed wildcard trusted origin pattern.
type wildcardOrigin struct {
	prefix string
	suffix string
}

func (w wildcardOrigin) match(origin string) bool {
	return len(origin) >= len(w.prefix)+len(w.suffix)+1 &&
		strings.HasPrefix(origin, w.prefix) &&
		strings.HasSuffix(origin, w.suffix)
}

func (cfg Config) validate() {
	validateTokenLookup(cfg.TokenLookup)
	if cfg.TokenLength > 32 {
		panic("csrf: TokenLength must not exceed 32")
	}
	if cfg.CookieSameSite == celeris.SameSiteNoneMode && !cfg.CookieSecure {
		panic("csrf: CookieSecure must be true when CookieSameSite is None")
	}
	if cfg.SingleUseToken && cfg.Storage == nil {
		panic("csrf: SingleUseToken requires Storage to be set")
	}
	for _, o := range cfg.TrustedOrigins {
		if strings.Contains(o, "*") && !strings.HasPrefix(o, "https://") {
			panic("csrf: wildcard TrustedOrigins must use https:// scheme, got " + o)
		}
	}
}

func validateTokenLookup(lookup string) {
	segments := strings.Split(lookup, ",")
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		parts := strings.SplitN(seg, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			panic("csrf: TokenLookup must be in the format \"source:name\" (e.g. \"header:X-CSRF-Token\")")
		}
		source := strings.ToLower(parts[0])
		if source != "header" && source != "form" && source != "query" {
			panic("csrf: TokenLookup source must be \"header\", \"form\", or \"query\", got \"" + parts[0] + "\"")
		}
	}
}
