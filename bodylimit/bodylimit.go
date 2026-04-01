package bodylimit

import "github.com/goceleris/celeris"

var errBodyTooLarge = celeris.NewHTTPError(413, "Request Entity Too Large")

// New creates a body limit middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	maxBytes := cfg.MaxBytes

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		cl := c.ContentLength()
		if cl > maxBytes {
			return errBodyTooLarge
		}

		return c.Next()
	}
}
