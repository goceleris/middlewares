package basicauth

import "github.com/goceleris/celeris"

// ErrUnauthorized is returned when authentication fails.
var ErrUnauthorized = celeris.NewHTTPError(401, "Unauthorized")

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

	realmHeader := `Basic realm="` + cfg.Realm + `"`
	validator := cfg.Validator
	validatorCtx := cfg.ValidatorWithContext
	errorHandler := cfg.ErrorHandler

	if errorHandler == nil {
		errorHandler = func(c *celeris.Context) error {
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
			return errorHandler(c)
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
