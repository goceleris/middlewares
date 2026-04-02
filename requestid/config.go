package requestid

import "github.com/goceleris/celeris"

// Config defines the request ID middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// Generator returns a new request ID. Default: buffered UUID v4.
	Generator func() string

	// Header is the header name to read/write. Default: "x-request-id".
	Header string

	// DisableTrustProxy, when true, ignores inbound request ID headers
	// and always generates a fresh ID. This prevents request ID spoofing
	// from untrusted clients. Default: false (inbound headers are trusted).
	DisableTrustProxy bool

	// TrustProxy is deprecated: use DisableTrustProxy instead.
	// When explicitly set to a non-nil *bool, it overrides DisableTrustProxy
	// in applyDefaults for backward compatibility:
	//   *TrustProxy == true  → DisableTrustProxy = false
	//   *TrustProxy == false → DisableTrustProxy = true
	//
	// Deprecated: Use DisableTrustProxy.
	TrustProxy *bool

	// AfterGenerate is called after a request ID is generated or extracted.
	// It receives the context and the request ID. Use it for logging, tracing,
	// or storing the ID in additional locations.
	AfterGenerate func(c *celeris.Context, id string)
}

// boolPtr returns a pointer to b.
func boolPtr(b bool) *bool { return &b }

// DefaultConfig is the default request ID configuration.
var DefaultConfig = Config{
	Header: "x-request-id",
}

func applyDefaults(cfg Config) Config {
	if cfg.Generator == nil {
		cfg.Generator = defaultGenerator.UUID
	}
	if cfg.Header == "" {
		cfg.Header = "x-request-id"
	}
	// Backward compatibility: TrustProxy (deprecated) overrides DisableTrustProxy.
	if cfg.TrustProxy != nil {
		cfg.DisableTrustProxy = !*cfg.TrustProxy
	}
	return cfg
}

func (cfg Config) validate() {}

var defaultGenerator = newBufferedGenerator()
