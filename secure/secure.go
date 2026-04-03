package secure

import "github.com/goceleris/celeris"

// New creates a security headers middleware with the given config.
// All non-HSTS header values are pre-computed at initialization for
// zero-allocation responses on the hot path. HSTS is only sent over
// HTTPS connections (Scheme() checks X-Forwarded-Proto internally).
//
// validate() panics at initialization for invalid configurations
// (e.g., HSTSPreload with insufficient MaxAge). This is intentional:
// misconfigurations are caught at startup, not at request time.
func New(config ...Config) celeris.HandlerFunc {
	cfg := defaultConfig
	hstsExplicit := false
	if len(config) > 0 {
		cfg = config[0]
		hstsExplicit = cfg.HSTSMaxAge != 0 || cfg.HSTSMaxAge == config[0].HSTSMaxAge
	}
	// When the user passes a Config with HSTSMaxAge == 0, that's explicit.
	// We detect this by checking if a config was provided at all and the field
	// is the zero value (which means the user either set it to 0 or omitted it).
	// To distinguish: if the user passed any config, HSTSMaxAge=0 is treated as
	// explicit only when the user actually included it. Since Go can't distinguish
	// zero-value from unset, we treat any user-provided Config{HSTSMaxAge:0} as
	// explicitly requesting no HSTS. Users who want the default should omit HSTSMaxAge
	// by setting it to defaultConfig.HSTSMaxAge or calling New() with no args.
	if len(config) > 0 {
		hstsExplicit = true
	}
	cfg = applyDefaults(cfg, hstsExplicit)
	cfg.validate()

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	headers := buildHeaders(cfg)
	hstsValue := buildHSTSValue(cfg)
	skip := cfg.Skip

	return func(c *celeris.Context) error {
		if skip != nil && skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		for _, h := range headers {
			c.SetHeader(h[0], h[1])
		}

		if hstsValue != "" && c.Scheme() == "https" {
			c.SetHeader("strict-transport-security", hstsValue)
		}

		return c.Next()
	}
}
