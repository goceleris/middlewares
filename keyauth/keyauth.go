package keyauth

import "github.com/goceleris/celeris"

// ErrUnauthorized is returned when the API key is invalid.
var ErrUnauthorized = celeris.NewHTTPError(401, "Unauthorized")

// ErrMissingKey is returned when no API key is found in the request.
var ErrMissingKey = celeris.NewHTTPError(401, "Missing API key")

// New creates a key auth middleware with the given config.
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

	extract := parseKeyLookup(cfg.KeyLookup)
	validator := cfg.Validator
	successHandler := cfg.SuccessHandler
	errorHandler := cfg.ErrorHandler
	wwwAuth := wwwAuthenticateValue(cfg.AuthScheme, cfg.Realm)

	if errorHandler == nil {
		errorHandler = func(_ *celeris.Context, err error) error {
			return err
		}
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		key := extract(c)
		if key == "" {
			c.SetHeader("www-authenticate", wwwAuth)
			return errorHandler(c, ErrMissingKey)
		}

		valid, err := validator(c, key)
		if err != nil {
			c.SetHeader("www-authenticate", wwwAuth)
			return errorHandler(c, err)
		}
		if !valid {
			c.SetHeader("www-authenticate", wwwAuth)
			return errorHandler(c, ErrUnauthorized)
		}

		c.Set(ContextKey, key)
		if successHandler != nil {
			successHandler(c)
		}
		return c.Next()
	}
}

// KeyFromContext returns the authenticated API key from the context store.
// Returns an empty string if no key was stored (e.g., no auth or skipped).
func KeyFromContext(c *celeris.Context) string {
	v, ok := c.Get(ContextKey)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
