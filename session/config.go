package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

// ContextKey is the context store key for the session object.
const ContextKey = "session"

// absExpKey is the reserved session data key for absolute expiry timestamp.
const absExpKey = "_abs_exp"

// Extractor is a function that extracts the session ID from a request.
// The default extractor reads the session cookie. For API clients, use
// [HeaderExtractor] or [QueryExtractor] instead.
type Extractor func(c *celeris.Context) string

// CookieExtractor returns an [Extractor] that reads the session ID from
// the named cookie.
func CookieExtractor(cookieName string) Extractor {
	return func(c *celeris.Context) string {
		v, err := c.Cookie(cookieName)
		if err != nil {
			return ""
		}
		return v
	}
}

// HeaderExtractor returns an [Extractor] that reads the session ID from
// the named request header. Use this for API clients that cannot store
// cookies.
func HeaderExtractor(headerName string) Extractor {
	return func(c *celeris.Context) string {
		return c.Header(headerName)
	}
}

// QueryExtractor returns an [Extractor] that reads the session ID from
// the named query parameter.
func QueryExtractor(paramName string) Extractor {
	return func(c *celeris.Context) string {
		return c.Query(paramName)
	}
}

// Config defines the session middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// Store is the session backend. Default: NewMemoryStore().
	Store Store

	// Extractor extracts the session ID from the request. Default:
	// CookieExtractor(CookieName). When a non-cookie extractor is used,
	// the session ID is also set in a response header named after the
	// cookie name for API clients.
	Extractor Extractor

	// CookieName is the session cookie name. Default: "celeris_session".
	CookieName string

	// CookiePath is the cookie Path attribute. Default: "/".
	CookiePath string

	// CookieDomain is the cookie Domain attribute.
	CookieDomain string

	// CookieMaxAge is the cookie Max-Age in seconds. Default: 86400 (24h).
	CookieMaxAge int

	// CookieSecure flags the cookie for HTTPS-only transmission.
	CookieSecure bool

	// CookieHTTPOnly prevents client-side scripts from accessing the cookie.
	// Default: true. To disable, set DisableCookieHTTPOnly to true.
	CookieHTTPOnly bool

	// DisableCookieHTTPOnly explicitly disables the HTTPOnly flag on the
	// session cookie. When true, CookieHTTPOnly is forced to false.
	DisableCookieHTTPOnly bool

	// CookieSessionOnly, when true, omits the Max-Age attribute from the
	// cookie so it becomes a browser-session-scoped cookie (deleted when
	// the browser closes).
	CookieSessionOnly bool

	// CookieSameSite controls cross-site request cookie behavior.
	// Default: celeris.SameSiteLaxMode.
	CookieSameSite celeris.SameSite

	// IdleTimeout is how long a session can be idle before expiring.
	// Default: 30 minutes.
	IdleTimeout time.Duration

	// AbsoluteTimeout is the maximum lifetime of a session regardless of
	// activity. Default: 24 hours. Set to 0 for the default, or -1 to
	// disable absolute timeout enforcement entirely.
	AbsoluteTimeout time.Duration

	// KeyGenerator generates new session IDs. Default: 32-byte crypto/rand hex.
	KeyGenerator func() string

	// SessionIDLength is the expected hex-encoded session ID length.
	// Used for validating incoming session IDs before store lookup.
	// Default: 64 (32 random bytes hex-encoded). Set this if you use
	// a custom KeyGenerator that produces IDs of a different length.
	// Set to -1 to disable length validation entirely.
	SessionIDLength int

	// ErrorHandler is called when a store operation fails. If nil, the error
	// is returned up the middleware chain.
	ErrorHandler func(c *celeris.Context, err error) error
}

// DefaultConfig is the default session configuration.
var DefaultConfig = Config{
	CookieName:      "celeris_session",
	CookiePath:      "/",
	CookieMaxAge:    86400,
	CookieHTTPOnly:  true,
	CookieSameSite:  celeris.SameSiteLaxMode,
	IdleTimeout:     30 * time.Minute,
	AbsoluteTimeout: 24 * time.Hour,
	SessionIDLength: 64,
}

// ChainExtractor returns an [Extractor] that tries each extractor in order
// and returns the first non-empty result. This is useful when session IDs
// may arrive via different transport mechanisms (e.g., cookie for browsers,
// header for API clients).
func ChainExtractor(extractors ...Extractor) Extractor {
	return func(c *celeris.Context) string {
		for _, e := range extractors {
			if sid := e(c); sid != "" {
				return sid
			}
		}
		return ""
	}
}

func applyDefaults(cfg Config) Config {
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
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
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultConfig.IdleTimeout
	}
	// AbsoluteTimeout: 0 → default (24h), -1 → disabled, >0 → as-is.
	if cfg.AbsoluteTimeout == 0 {
		cfg.AbsoluteTimeout = DefaultConfig.AbsoluteTimeout
	}
	if cfg.KeyGenerator == nil {
		cfg.KeyGenerator = newBufferedKeyGenerator().generate
	}
	if cfg.SessionIDLength == 0 {
		cfg.SessionIDLength = DefaultConfig.SessionIDLength
	}
	if cfg.DisableCookieHTTPOnly {
		cfg.CookieHTTPOnly = false
	} else if !cfg.CookieHTTPOnly {
		cfg.CookieHTTPOnly = DefaultConfig.CookieHTTPOnly
	}
	return cfg
}

func (cfg Config) validate() {
	if cfg.AbsoluteTimeout > 0 && cfg.AbsoluteTimeout < cfg.IdleTimeout {
		panic("session: AbsoluteTimeout must be >= IdleTimeout")
	}
	if cfg.CookieSameSite == celeris.SameSiteNoneMode && !cfg.CookieSecure {
		panic("session: CookieSecure must be true when CookieSameSite is None")
	}
}

// bufferedKeyGenerator batches crypto/rand reads into a 4096-byte buffer,
// amortizing syscall overhead across 128 session IDs (32 bytes each).
const keyBytes = 32
const keyBufSize = keyBytes * 128 // 4096 bytes

type bufferedKeyGenerator struct {
	mu  sync.Mutex
	buf [keyBufSize]byte
	pos int
}

func newBufferedKeyGenerator() *bufferedKeyGenerator {
	return &bufferedKeyGenerator{pos: keyBufSize}
}

func (g *bufferedKeyGenerator) generate() string {
	g.mu.Lock()
	if g.pos >= keyBufSize {
		if _, err := rand.Read(g.buf[:]); err != nil {
			panic("session: crypto/rand failed: " + err.Error())
		}
		g.pos = 0
	}
	var raw [keyBytes]byte
	copy(raw[:], g.buf[g.pos:g.pos+keyBytes])
	g.pos += keyBytes
	g.mu.Unlock()

	var dst [keyBytes * 2]byte
	hex.Encode(dst[:], raw[:])
	return string(dst[:])
}
