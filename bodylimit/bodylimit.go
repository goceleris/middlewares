package bodylimit

import "github.com/goceleris/celeris"

// ErrBodyTooLarge is returned when the request body exceeds the configured limit.
var ErrBodyTooLarge = celeris.NewHTTPError(413, "Request Entity Too Large")

// New creates a body limit middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	validate(&cfg)

	maxBytes := cfg.MaxBytes
	errHandler := cfg.ErrorHandler

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		// Auto-skip bodyless methods.
		switch c.Method() {
		case "GET", "HEAD", "DELETE", "OPTIONS":
			return c.Next()
		}

		cl := c.ContentLength()
		if cl > maxBytes {
			if errHandler != nil {
				return errHandler(c, ErrBodyTooLarge)
			}
			return ErrBodyTooLarge
		}
		if int64(len(c.Body())) > maxBytes {
			if errHandler != nil {
				return errHandler(c, ErrBodyTooLarge)
			}
			return ErrBodyTooLarge
		}

		return c.Next()
	}
}
