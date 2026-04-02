package keyauth

import (
	"crypto/subtle"
	"fmt"
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
}

// DefaultConfig is the default key auth configuration.
var DefaultConfig = Config{
	KeyLookup: "header:X-API-Key",
}

func applyDefaults(cfg Config) Config {
	if cfg.KeyLookup == "" {
		cfg.KeyLookup = DefaultConfig.KeyLookup
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
}

// StaticKeys returns a constant-time validator that checks the key against a
// fixed set of valid keys. All comparisons use a uniform code path to prevent
// timing side-channels on key existence or length.
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
		var kb []byte
		if maxLen <= 256 {
			var buf [256]byte
			kb = buf[:maxLen]
			copy(kb, key)
			for i := len(key); i < maxLen; i++ {
				kb[i] = 0
			}
		} else {
			kb = padTo([]byte(key), maxLen)
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

func wwwAuthenticateValue(scheme, realm string) string {
	if scheme != "" {
		return fmt.Sprintf(`%s realm="%s"`, scheme, realm)
	}
	return fmt.Sprintf(`ApiKey realm="%s"`, realm)
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
