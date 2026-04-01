package requestid

import "github.com/goceleris/celeris"

// New creates a request ID middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	header := cfg.Header
	gen := cfg.Generator

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		id := c.Header(header)
		if id == "" {
			id = gen()
		}

		c.SetHeader(header, id)
		c.Set("request_id", id)
		return c.Next()
	}
}
