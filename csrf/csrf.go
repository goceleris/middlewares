package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

// ContextKey is the default context store key for the CSRF token.
const ContextKey = "csrf_token"

// handlerContextKey is the context store key for the Handler instance.
const handlerContextKey = "csrf_handler"

// ErrForbidden is returned when the submitted CSRF token does not match
// the cookie token.
var ErrForbidden = celeris.NewHTTPError(403, "Forbidden")

// ErrMissingToken is returned when the CSRF token is absent from the
// cookie or the request source.
var ErrMissingToken = celeris.NewHTTPError(403, "Missing CSRF token")

// ErrTokenNotFound is returned by DeleteToken when no token exists.
var ErrTokenNotFound = celeris.NewHTTPError(404, "Token not found")

// ErrOriginMismatch is returned when the Origin header does not match
// the request host or any trusted origin.
var ErrOriginMismatch = celeris.NewHTTPError(403, "csrf: origin does not match")

// ErrRefererMissing is returned when the Referer header is absent on an
// HTTPS request with no Origin header.
var ErrRefererMissing = celeris.NewHTTPError(403, "csrf: referer header missing")

// ErrRefererMismatch is returned when the Referer header does not match
// the request host or any trusted origin.
var ErrRefererMismatch = celeris.NewHTTPError(403, "csrf: referer does not match")

// ErrSecFetchSite is returned when the Sec-Fetch-Site header value is
// "cross-site", indicating a cross-site request.
var ErrSecFetchSite = celeris.NewHTTPError(403, "csrf: sec-fetch-site is cross-site")

// tokenExtractor extracts a token string from the request.
type tokenExtractor func(c *celeris.Context) string

// Handler provides methods for managing CSRF tokens for a specific
// middleware configuration. Retrieved via HandlerFromContext.
type Handler struct {
	storage           Storage
	expiration        time.Duration
	cookieName        string
	cookiePath        string
	cookieDomain      string
	cookieSecure      bool
	cookieHTTPOnly    bool
	cookieSameSite    celeris.SameSite
	cookieSessionOnly bool
	contextKey        string
}

// DeleteToken removes the CSRF token from server-side storage and
// expires the cookie. Useful for logout flows. Returns ErrTokenNotFound
// if no token exists in the cookie.
func (h *Handler) DeleteToken(c *celeris.Context) error {
	cookieToken, err := c.Cookie(h.cookieName)
	if err != nil || cookieToken == "" {
		return ErrTokenNotFound
	}
	if h.storage != nil {
		h.storage.Delete(cookieToken)
	}
	c.SetCookie(&celeris.Cookie{
		Name:     h.cookieName,
		Value:    "",
		Path:     h.cookiePath,
		Domain:   h.cookieDomain,
		MaxAge:   -1,
		Secure:   h.cookieSecure,
		HTTPOnly: h.cookieHTTPOnly,
		SameSite: h.cookieSameSite,
	})
	return nil
}

// New creates a CSRF middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	safeMap := make(map[string]struct{}, len(cfg.SafeMethods))
	for _, m := range cfg.SafeMethods {
		safeMap[m] = struct{}{}
	}

	// Parse trusted origins: separate exact matches from wildcard patterns.
	trustedOrigins := make(map[string]struct{})
	var wildcardOrigins []wildcardOrigin
	for _, o := range cfg.TrustedOrigins {
		if strings.Contains(o, "*") {
			idx := strings.Index(o, "*")
			wildcardOrigins = append(wildcardOrigins, wildcardOrigin{
				prefix: o[:idx],
				suffix: o[idx+1:],
			})
		} else {
			trustedOrigins[o] = struct{}{}
		}
	}

	extractor := buildExtractor(cfg.TokenLookup)
	tokenLen := cfg.TokenLength
	cookieName := cfg.CookieName
	cookiePath := cfg.CookiePath
	cookieDomain := cfg.CookieDomain
	cookieMaxAge := cfg.CookieMaxAge
	cookieSecure := cfg.CookieSecure
	cookieHTTPOnly := cfg.CookieHTTPOnly
	cookieSameSite := cfg.CookieSameSite
	cookieSessionOnly := cfg.CookieSessionOnly
	contextKey := cfg.ContextKey
	storage := cfg.Storage
	expiration := cfg.Expiration
	singleUse := cfg.SingleUseToken
	keyGen := cfg.KeyGenerator

	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = func(_ *celeris.Context, err error) error { return err }
	}

	genToken := func() string {
		if keyGen != nil {
			return keyGen()
		}
		return generateToken(tokenLen)
	}

	handler := &Handler{
		storage:           storage,
		expiration:        expiration,
		cookieName:        cookieName,
		cookiePath:        cookiePath,
		cookieDomain:      cookieDomain,
		cookieSecure:      cookieSecure,
		cookieHTTPOnly:    cookieHTTPOnly,
		cookieSameSite:    cookieSameSite,
		cookieSessionOnly: cookieSessionOnly,
		contextKey:        contextKey,
	}

	setCookie := func(c *celeris.Context, token string) {
		cookie := &celeris.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     cookiePath,
			Domain:   cookieDomain,
			Secure:   cookieSecure,
			HTTPOnly: cookieHTTPOnly,
			SameSite: cookieSameSite,
		}
		if !cookieSessionOnly {
			cookie.MaxAge = cookieMaxAge
		}
		c.SetCookie(cookie)
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		c.Set(handlerContextKey, handler)

		_, safe := safeMap[c.Method()]

		if safe {
			token, err := c.Cookie(cookieName)
			if err != nil || token == "" {
				token = genToken()
			} else if storage != nil {
				// In storage mode, verify the cookie token still exists.
				if _, ok := storage.Get(token); !ok {
					token = genToken()
				}
			}
			if storage != nil {
				storage.Set(token, token, expiration)
			}
			setCookie(c, token)
			c.AddHeader("vary", "Cookie")
			c.Set(contextKey, token)
			return c.Next()
		}

		// Defense-in-depth: reject cross-site requests via Sec-Fetch-Site.
		if sfs := c.Header("sec-fetch-site"); sfs == "cross-site" {
			return errorHandler(c, ErrSecFetchSite)
		}

		// Defense-in-depth: validate Origin header against request host.
		origin := c.Header("origin")
		if origin != "" {
			if !isOriginAllowed(origin, c.Host(), trustedOrigins, wildcardOrigins) {
				return errorHandler(c, ErrOriginMismatch)
			}
		}

		// Referer fallback when Origin is absent on HTTPS.
		if origin == "" && c.Scheme() == "https" {
			referer := c.Header("referer")
			if referer == "" {
				return errorHandler(c, ErrRefererMissing)
			}
			if !isOriginAllowed(referer, c.Host(), trustedOrigins, wildcardOrigins) {
				return errorHandler(c, ErrRefererMismatch)
			}
		}

		cookieToken, err := c.Cookie(cookieName)
		if err != nil || cookieToken == "" {
			return errorHandler(c, ErrMissingToken)
		}

		requestToken := extractor(c)
		if requestToken == "" {
			return errorHandler(c, ErrMissingToken)
		}

		if storage != nil {
			// Server-side validation: token must exist in storage.
			storedToken, ok := storage.Get(cookieToken)
			if !ok {
				return errorHandler(c, ErrForbidden)
			}
			if subtle.ConstantTimeCompare([]byte(storedToken), []byte(requestToken)) != 1 {
				return errorHandler(c, ErrForbidden)
			}
			if singleUse {
				storage.Delete(cookieToken)
			}
		} else {
			if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(requestToken)) != 1 {
				return errorHandler(c, ErrForbidden)
			}
		}

		c.AddHeader("vary", "Cookie")
		c.Set(contextKey, cookieToken)
		return c.Next()
	}
}

// isOriginAllowed checks if the request origin matches the host, an exact
// trusted origin, or a wildcard trusted origin pattern.
func isOriginAllowed(origin, host string, trusted map[string]struct{}, wildcards []wildcardOrigin) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := parsed.Host
	if originHost == "" {
		return false
	}
	if originHost == host {
		return true
	}
	if _, ok := trusted[origin]; ok {
		return true
	}
	for i := range wildcards {
		if wildcards[i].match(origin) {
			return true
		}
	}
	return false
}

// TokenFromContext returns the CSRF token from the context store.
// Returns an empty string if no token was stored (e.g., skipped request).
// When the middleware is configured with a custom ContextKey, the handler's
// key is tried first, falling back to the default ContextKey constant.
func TokenFromContext(c *celeris.Context) string {
	if h := handlerFromContext(c); h != nil {
		v, ok := c.Get(h.contextKey)
		if ok {
			s, _ := v.(string)
			return s
		}
	}
	v, ok := c.Get(ContextKey)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// HandlerFromContext returns the Handler associated with the CSRF middleware
// from the request context. Returns nil if the middleware has not run.
func HandlerFromContext(c *celeris.Context) *Handler {
	return handlerFromContext(c)
}

func handlerFromContext(c *celeris.Context) *Handler {
	v, ok := c.Get(handlerContextKey)
	if !ok {
		return nil
	}
	h, _ := v.(*Handler)
	return h
}

// DeleteToken removes the CSRF token from server-side storage and expires
// the cookie. This is a convenience wrapper around HandlerFromContext.
// Returns ErrTokenNotFound if no token or handler exists.
func DeleteToken(c *celeris.Context) error {
	h := handlerFromContext(c)
	if h == nil {
		return ErrTokenNotFound
	}
	return h.DeleteToken(c)
}

// buildExtractor parses the TokenLookup string (possibly comma-separated)
// and returns an extractor that tries each source in order.
func buildExtractor(lookup string) tokenExtractor {
	segments := strings.Split(lookup, ",")
	if len(segments) == 1 {
		return buildSingleExtractor(strings.TrimSpace(segments[0]))
	}
	extractors := make([]tokenExtractor, len(segments))
	for i, seg := range segments {
		extractors[i] = buildSingleExtractor(strings.TrimSpace(seg))
	}
	return func(c *celeris.Context) string {
		for _, e := range extractors {
			if v := e(c); v != "" {
				return v
			}
		}
		return ""
	}
}

func buildSingleExtractor(lookup string) tokenExtractor {
	parts := strings.SplitN(lookup, ":", 2)
	source := strings.ToLower(parts[0])
	name := parts[1]

	switch source {
	case "header":
		key := strings.ToLower(name)
		return func(c *celeris.Context) string {
			return c.Header(key)
		}
	case "form":
		return func(c *celeris.Context) string {
			return c.FormValue(name)
		}
	case "query":
		return func(c *celeris.Context) string {
			return c.Query(name)
		}
	default:
		panic("csrf: unsupported TokenLookup source: " + source)
	}
}

const tokenBufSize = 32 * 128 // 4096 bytes = 128 tokens at 32 bytes each

type bufferedTokenGen struct {
	mu  sync.Mutex
	buf [tokenBufSize]byte
	pos int
}

var tokenGen = &bufferedTokenGen{pos: tokenBufSize}

// generateToken produces a hex-encoded random token of the given byte length.
// Uses a mutex-protected 4096-byte buffer filled from crypto/rand to amortize
// syscall overhead. Panics if crypto/rand fails (security-critical).
func generateToken(length int) string {
	g := tokenGen
	g.mu.Lock()
	remaining := tokenBufSize - g.pos
	if remaining < length {
		if _, err := rand.Read(g.buf[:]); err != nil {
			g.mu.Unlock()
			panic("csrf: crypto/rand failed: " + err.Error())
		}
		g.pos = 0
	}
	var raw [32]byte
	copy(raw[:length], g.buf[g.pos:g.pos+length])
	g.pos += length
	g.mu.Unlock()

	var dst [64]byte
	hex.Encode(dst[:length*2], raw[:length])
	return string(dst[:length*2])
}
