package basicauth

import (
	"strings"

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
