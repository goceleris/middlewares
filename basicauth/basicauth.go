package basicauth

import "github.com/goceleris/celeris"

var errUnauthorized = celeris.NewHTTPError(401, "Unauthorized")

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
	errorHandler := cfg.ErrorHandler

	if errorHandler == nil {
		errorHandler = func(c *celeris.Context) error {
			c.SetHeader("www-authenticate", realmHeader)
			return errUnauthorized
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
		if !ok || !validator(user, pass) {
			return errorHandler(c)
		}

		c.Set("user", user)
		return c.Next()
	}
}
