package csrf

import (
	"crypto/rand"
	"crypto/sha256"
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

// Sentinel errors returned by the CSRF middleware. These are package-level
// variables for use with errors.Is. Do not reassign them.
var (
	// ErrForbidden is returned when the submitted CSRF token does not match
	// the cookie token.
	ErrForbidden = celeris.NewHTTPError(403, "Forbidden")

	// ErrMissingToken is returned when the CSRF token is absent from the
	// cookie or the request source.
	ErrMissingToken = celeris.NewHTTPError(403, "Missing CSRF token")

	// ErrTokenNotFound is returned by DeleteToken when no token exists.
	ErrTokenNotFound = celeris.NewHTTPError(404, "Token not found")

	// ErrOriginMismatch is returned when the Origin header does not match
	// the request host or any trusted origin.
	ErrOriginMismatch = celeris.NewHTTPError(403, "csrf: origin does not match")

	// ErrRefererMissing is returned when the Referer header is absent on an
	// HTTPS request with no Origin header.
	ErrRefererMissing = celeris.NewHTTPError(403, "csrf: referer header missing")

	// ErrRefererMismatch is returned when the Referer header does not match
	// the request host or any trusted origin.
	ErrRefererMismatch = celeris.NewHTTPError(403, "csrf: referer does not match")

	// ErrSecFetchSite is returned when the Sec-Fetch-Site header value is
	// "cross-site", indicating a cross-site request.
	ErrSecFetchSite = celeris.NewHTTPError(403, "csrf: sec-fetch-site is cross-site")
)

// tokenExtractor extracts a token string from the request.
type tokenExtractor func(c *celeris.Context) string

// Handler provides methods for managing CSRF tokens for a specific
// middleware configuration. Retrieved via HandlerFromContext.
type Handler struct {
	storage           Storage
	expiration        time.Duration
	tokenLen          int
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
		h.storage.Delete(storageKey(unmaskToken(cookieToken, h.tokenLen)))
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
		tokenLen:          tokenLen,
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
			newToken := false
			if err != nil || token == "" {
				token = genToken()
				newToken = true
			} else if storage != nil {
				// In storage mode, verify the cookie token still exists.
				// Unmask the cookie to recover the raw token for storage lookup.
				raw := unmaskToken(token, tokenLen)
				if _, ok := storage.Get(storageKey(raw)); !ok {
					token = genToken()
					newToken = true
				} else {
					token = raw
				}
			} else {
				// Pure double-submit: unmask the cookie to get the raw token.
				token = unmaskToken(token, tokenLen)
			}
			if storage != nil && newToken {
				storage.Set(storageKey(token), token, expiration)
			}
			// BREACH mitigation: mask the token per-request so the
			// cookie value changes on every response, defeating
			// compression side-channel attacks.
			masked := maskToken(token, tokenLen)
			setCookie(c, masked)
			c.AddHeader("vary", "Cookie")
			c.Set(contextKey, masked)
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
			refOrigin := extractOrigin(referer)
			if refOrigin == "" {
				return errorHandler(c, ErrRefererMismatch)
			}
			if !isOriginAllowed(refOrigin, c.Host(), trustedOrigins, wildcardOrigins) {
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

		// Unmask both tokens to recover the real values before comparison.
		realCookie := unmaskToken(cookieToken, tokenLen)
		realRequest := unmaskToken(requestToken, tokenLen)

		if storage != nil {
			key := storageKey(realCookie)
			var storedToken string
			var ok bool
			if singleUse {
				// Atomic get-and-delete prevents TOCTOU race on single-use tokens.
				var err error
				storedToken, ok, err = storage.GetAndDelete(key)
				if err != nil {
					return errorHandler(c, ErrForbidden)
				}
			} else {
				storedToken, ok = storage.Get(key)
			}
			if !ok {
				return errorHandler(c, ErrForbidden)
			}
			if subtle.ConstantTimeCompare([]byte(storedToken), []byte(realRequest)) != 1 {
				return errorHandler(c, ErrForbidden)
			}
		} else {
			if subtle.ConstantTimeCompare([]byte(realCookie), []byte(realRequest)) != 1 {
				return errorHandler(c, ErrForbidden)
			}
		}

		c.AddHeader("vary", "Cookie")
		c.Set(contextKey, cookieToken)
		return c.Next()
	}
}

// maskToken generates a random mask of tokenByteLen bytes, XORs the
// decoded token bytes, and returns hex(mask)+hex(masked). The result
// changes on every call even for the same token, preventing BREACH
// compression side-channel attacks. If the token cannot be decoded as
// hex or has the wrong byte length, it is returned as-is.
func maskToken(token string, tokenByteLen int) string {
	raw, err := hex.DecodeString(token)
	if err != nil || len(raw) != tokenByteLen {
		return token
	}
	mask := make([]byte, tokenByteLen)
	if _, err := rand.Read(mask); err != nil {
		panic("csrf: crypto/rand failed: " + err.Error())
	}
	masked := make([]byte, tokenByteLen)
	for i := range raw {
		masked[i] = raw[i] ^ mask[i]
	}
	return hex.EncodeToString(mask) + hex.EncodeToString(masked)
}

// unmaskToken reverses maskToken. A masked token has exactly
// 4*tokenByteLen hex chars (two concatenated hex-encoded halves).
// If the input matches this length, the halves are decoded, XORed,
// and the original token is returned. Otherwise the input is returned
// as-is for backward compatibility with unmasked tokens.
func unmaskToken(token string, tokenByteLen int) string {
	expected := tokenByteLen * 4
	if len(token) != expected {
		return token
	}
	half := expected / 2
	maskBytes, err := hex.DecodeString(token[:half])
	if err != nil {
		return token
	}
	maskedBytes, err := hex.DecodeString(token[half:])
	if err != nil {
		return token
	}
	raw := make([]byte, tokenByteLen)
	for i := range maskBytes {
		raw[i] = maskBytes[i] ^ maskedBytes[i]
	}
	return hex.EncodeToString(raw)
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

// extractOrigin parses a URL and returns scheme + "://" + host.
// Returns an empty string if parsing fails or the host is absent.
func extractOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// storageKey returns a SHA-256 hex digest of the token for use as a storage key.
// This prevents leaking raw tokens through the storage backend.
func storageKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
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
	if len(parts) != 2 || parts[1] == "" {
		panic("csrf: TokenLookup segment must be \"source:name\", got \"" + lookup + "\"")
	}
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
		n, err := rand.Read(g.buf[:])
		if err != nil {
			g.mu.Unlock()
			panic("csrf: crypto/rand failed: " + err.Error())
		}
		if n < tokenBufSize {
			g.mu.Unlock()
			panic("csrf: crypto/rand short read")
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
