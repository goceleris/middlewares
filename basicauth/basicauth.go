package basicauth

import (
	"strings"
	"unicode/utf8"

	"github.com/goceleris/celeris"
)

// ErrUnauthorized is returned when authentication fails.
var ErrUnauthorized = celeris.NewHTTPError(401, "Unauthorized")

// ErrHeaderTooLarge is returned when the Authorization header exceeds HeaderLimit.
var ErrHeaderTooLarge = celeris.NewHTTPError(431, "Request Header Fields Too Large")

// New creates a basic auth middleware with the given config.
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

	escapedRealm := strings.ReplaceAll(cfg.Realm, `\`, `\\`)
	escapedRealm = strings.ReplaceAll(escapedRealm, `"`, `\"`)
	realmHeader := `Basic realm="` + escapedRealm + `"`
	validator := cfg.Validator
	validatorCtx := cfg.ValidatorWithContext
	headerLimit := cfg.HeaderLimit
	errorHandler := cfg.ErrorHandler

	if errorHandler == nil {
		errorHandler = func(c *celeris.Context, err error) error {
			if err == ErrHeaderTooLarge {
				return ErrHeaderTooLarge
			}
			c.SetHeader("www-authenticate", realmHeader)
			return ErrUnauthorized
		}
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		if len(c.Header("authorization")) > headerLimit {
			return errorHandler(c, ErrHeaderTooLarge)
		}

		user, pass, ok := c.BasicAuth()
		if ok && !validCredentialBytes(user, pass) {
			ok = false
		}
		var valid bool
		if ok {
			if validatorCtx != nil {
				valid = validatorCtx(c, user, pass)
			} else {
				valid = validator(user, pass)
			}
		}
		if !ok || !valid {
			return errorHandler(c, ErrUnauthorized)
		}

		c.Set(UsernameKey, user)
		return c.Next()
	}
}

// validCredentialBytes rejects credentials that contain invalid UTF-8
// sequences or ASCII control characters (bytes < 0x20 or DEL 0x7F).
//
// NFC normalization is intentionally omitted to avoid a dependency on
// golang.org/x/text. Callers storing passwords should normalize to NFC
// before hashing if Unicode equivalence matters.
func validCredentialBytes(user, pass string) bool {
	if !utf8.ValidString(user) || !utf8.ValidString(pass) {
		return false
	}
	for i := 0; i < len(user); i++ {
		if user[i] < 0x20 || user[i] == 0x7F {
			return false
		}
	}
	for i := 0; i < len(pass); i++ {
		if pass[i] < 0x20 || pass[i] == 0x7F {
			return false
		}
	}
	return true
}

// UsernameFromContext returns the authenticated username from the context store.
// Returns an empty string if no username was stored (e.g., no auth or skipped).
func UsernameFromContext(c *celeris.Context) string {
	v, ok := c.Get(UsernameKey)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
