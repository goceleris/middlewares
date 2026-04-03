package keyauth

import (
	"crypto/subtle"
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/goceleris/celeris"
)

// ContextKey is the context store key for the authenticated API key.
const ContextKey = "keyauth_key"

// Config defines the key auth middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// KeyLookup defines where to extract the API key.
	//
	// Format: "source:name" or "source:name:prefix" for prefix stripping.
	// Multiple sources can be comma-separated for fallback, e.g.
	// "header:Authorization:Bearer ,query:api_key".
	//
	// Supported sources: header, query, cookie, form, param.
	// Default: "header:X-API-Key".
	KeyLookup string

	// Validator checks the extracted key. Required -- panics if nil.
	Validator func(c *celeris.Context, key string) (bool, error)

	// SuccessHandler is called after a key is successfully validated,
	// before c.Next(). Use it to enrich the context (e.g., set tenant ID
	// based on key). If nil, no extra action is taken.
	SuccessHandler func(c *celeris.Context)

	// ErrorHandler handles authentication failures. Receives the error
	// (ErrMissingKey or ErrUnauthorized) and returns the error to propagate.
	// Default: returns the error as-is.
	ErrorHandler func(c *celeris.Context, err error) error

	// Realm is the realm value used in the WWW-Authenticate header on 401.
	// Default: "Restricted".
	Realm string

	// AuthScheme is the authentication scheme used in the WWW-Authenticate
	// header (e.g. "Bearer"). When empty, "ApiKey" is used as the scheme.
	AuthScheme string

	// ChallengeError is the RFC 6750 error code for WWW-Authenticate.
	// Valid values: "invalid_request", "invalid_token", "insufficient_scope".
	ChallengeError string

	// ChallengeErrorDescription is the RFC 6750 error_description for WWW-Authenticate.
	ChallengeErrorDescription string

	// ChallengeErrorURI is the RFC 6750 error_uri for WWW-Authenticate.
	ChallengeErrorURI string

	// ChallengeScope is the RFC 6750 scope for WWW-Authenticate.
	ChallengeScope string

	// ContinueOnIgnoredError, when true, allows the request to proceed
	// if ErrorHandler returns nil. This enables mixed public/private routes
	// where authentication is optional.
	ContinueOnIgnoredError bool
}

// defaultConfig is the default key auth configuration.
// It is unexported to prevent callers from mutating shared state.
// Use DefaultConfig() to obtain a copy.
var defaultConfig = Config{
	KeyLookup: "header:X-API-Key",
}

// DefaultConfig returns a copy of the default key auth configuration.
func DefaultConfig() Config {
	return defaultConfig
}

func applyDefaults(cfg Config) Config {
	if cfg.KeyLookup == "" {
		cfg.KeyLookup = defaultConfig.KeyLookup
	}
	if cfg.Realm == "" {
		cfg.Realm = "Restricted"
	}
	return cfg
}

func (cfg Config) validate() {
	if cfg.Validator == nil {
		panic("keyauth: Validator is required")
	}
	if cfg.AuthScheme != "" {
		for _, r := range cfg.AuthScheme {
			if !isTokenChar(r) {
				panic("keyauth: AuthScheme contains invalid character (must be HTTP token chars only)")
			}
		}
	}
	if cfg.Realm != "" {
		for _, r := range cfg.Realm {
			if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
				panic("keyauth: Realm contains invalid character (quotes, backslashes, and control chars are not allowed)")
			}
		}
	}
	if cfg.ChallengeError != "" {
		switch cfg.ChallengeError {
		case "invalid_request", "invalid_token", "insufficient_scope":
		default:
			panic("keyauth: ChallengeError must be \"invalid_request\", \"invalid_token\", or \"insufficient_scope\"")
		}
	}
	if cfg.ChallengeErrorURI != "" {
		u, err := url.Parse(cfg.ChallengeErrorURI)
		if err != nil || !u.IsAbs() {
			panic("keyauth: ChallengeErrorURI must be a valid absolute URI")
		}
	}
}

// isTokenChar reports whether r is a valid HTTP token character per RFC 7230 section 3.2.6.
func isTokenChar(r rune) bool {
	if r < '!' || r > '~' {
		return false
	}
	switch r {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
		return false
	}
	return true
}

// StaticKeys returns a constant-time validator that checks the key against a
// fixed set of valid keys. All comparisons use a uniform code path to prevent
// timing side-channels on key existence or length.
//
// Duplicate keys in the input are not deduplicated; each copy is compared
// independently. This has no effect on correctness.
func StaticKeys(keys ...string) func(*celeris.Context, string) (bool, error) {
	if len(keys) == 0 {
		return func(_ *celeris.Context, _ string) (bool, error) {
			return false, nil
		}
	}

	// Find the maximum key length and pad all keys at init time.
	maxLen := 0
	for _, k := range keys {
		if len(k) > maxLen {
			maxLen = len(k)
		}
	}
	padded := make([][]byte, len(keys))
	for i, k := range keys {
		padded[i] = padTo([]byte(k), maxLen)
	}

	return func(_ *celeris.Context, key string) (bool, error) {
		if len(key) > math.MaxInt32 {
			return false, nil
		}
		var kb []byte
		if maxLen <= 256 {
			var buf [256]byte
			kb = buf[:maxLen]
			clear(kb)
			copy(kb, key)
		} else {
			kb = padTo([]byte(key), maxLen) //nolint:staticcheck // kb is used in the loop below
		}
		match := 0
		for i, p := range padded {
			lenMatch := subtle.ConstantTimeEq(int32(len(keys[i])), int32(len(key)))
			cmp := subtle.ConstantTimeCompare(kb, p)
			match |= lenMatch & cmp
		}
		return match == 1, nil
	}
}

// padTo returns b right-padded with zero bytes to length n. If b is already
// at least n bytes, it is truncated to n.
func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

func wwwAuthenticateValue(cfg Config) string {
	var b strings.Builder
	if cfg.AuthScheme != "" {
		b.WriteString(cfg.AuthScheme)
	} else {
		b.WriteString("ApiKey")
	}
	fmt.Fprintf(&b, ` realm="%s"`, escapeQuotedString(cfg.Realm))
	if cfg.ChallengeScope != "" {
		fmt.Fprintf(&b, `, scope="%s"`, escapeQuotedString(cfg.ChallengeScope))
	}
	if cfg.ChallengeError != "" {
		fmt.Fprintf(&b, `, error="%s"`, cfg.ChallengeError)
	}
	if cfg.ChallengeErrorDescription != "" {
		fmt.Fprintf(&b, `, error_description="%s"`, escapeQuotedString(cfg.ChallengeErrorDescription))
	}
	if cfg.ChallengeErrorURI != "" {
		fmt.Fprintf(&b, `, error_uri="%s"`, cfg.ChallengeErrorURI)
	}
	return b.String()
}

// escapeQuotedString escapes backslashes and double-quotes for use in
// HTTP quoted-string values (RFC 7230 section 3.2.6).
func escapeQuotedString(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

type extractor func(c *celeris.Context) string

func parseKeyLookup(lookup string) extractor {
	sources := strings.Split(lookup, ",")
	extractors := make([]extractor, 0, len(sources))
	for _, src := range sources {
		extractors = append(extractors, parseSingleLookup(src))
	}
	if len(extractors) == 1 {
		return extractors[0]
	}
	return func(c *celeris.Context) string {
		for _, ex := range extractors {
			if v := ex(c); v != "" {
				return v
			}
		}
		return ""
	}
}

func parseSingleLookup(lookup string) extractor {
	parts := strings.SplitN(lookup, ":", 3)
	if len(parts) < 2 {
		panic("keyauth: invalid KeyLookup format: " + lookup)
	}
	source := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	prefix := ""
	if len(parts) == 3 {
		prefix = parts[2] // preserve whitespace in prefix (e.g. "Bearer ")
	}

	var base extractor
	switch source {
	case "header":
		key := strings.ToLower(name)
		base = func(c *celeris.Context) string { return c.Header(key) }
	case "query":
		base = func(c *celeris.Context) string { return c.Query(name) }
	case "cookie":
		base = func(c *celeris.Context) string { v, _ := c.Cookie(name); return v }
	case "form":
		base = func(c *celeris.Context) string { return c.FormValue(name) }
	case "param":
		base = func(c *celeris.Context) string { return c.Param(name) }
	default:
		panic("keyauth: unsupported KeyLookup source: " + source)
	}

	if prefix == "" {
		return base
	}

	return func(c *celeris.Context) string {
		v := base(c)
		if v == "" {
			return ""
		}
		after, found := strings.CutPrefix(v, prefix)
		if !found {
			return ""
		}
		return after
	}
}
