package cors

import "github.com/goceleris/celeris"

// New creates a CORS middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()
	p := precompute(cfg)

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		origin := c.Header("origin")

		// No Origin header — not a CORS request.
		if origin == "" {
			return c.Next()
		}

		// Check if origin is allowed.
		allowed := p.allowAllOrigins
		if !allowed {
			_, allowed = p.originSet[origin]
		}
		if !allowed {
			return c.Next()
		}

		// Set origin header.
		if p.allowAllOrigins {
			c.SetHeader("access-control-allow-origin", "*")
		} else {
			c.SetHeader("access-control-allow-origin", origin)
			c.SetHeader("vary", "Origin")
		}

		if cfg.AllowCredentials {
			c.SetHeader("access-control-allow-credentials", "true")
		}

		if p.exposeHeaders != "" {
			c.SetHeader("access-control-expose-headers", p.exposeHeaders)
		}

		// Preflight request.
		if c.Method() == "OPTIONS" {
			c.SetHeader("access-control-allow-methods", p.allowMethods)
			c.SetHeader("access-control-allow-headers", p.allowHeaders)
			if p.maxAge != "" {
				c.SetHeader("access-control-max-age", p.maxAge)
			}
			return c.NoContent(204)
		}

		return c.Next()
	}
}
