package requestid

import "github.com/goceleris/celeris"

// ContextKey is the context store key for the request ID.
const ContextKey = "request_id"

const maxIDLen = 128

// FromContext returns the request ID from the context store.
// Returns an empty string if no request ID was stored.
func FromContext(c *celeris.Context) string {
	v, ok := c.Get(ContextKey)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > maxIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7E {
			return false
		}
	}
	return true
}

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
	trustProxy := cfg.TrustProxy == nil || *cfg.TrustProxy

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

		var id string
		if trustProxy {
			id = c.Header(header)
			if !validID(id) {
				id = ""
			}
		}
		if id == "" {
			id = gen()
		}

		c.SetHeader(header, id)
		c.Set(ContextKey, id)
		return c.Next()
	}
}
