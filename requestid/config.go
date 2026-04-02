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

	// TrustProxy controls whether the inbound request header is accepted.
	// When true (default), a valid inbound header is propagated as-is.
	// When false, the inbound header is always ignored and a fresh ID is
	// generated. Set to false when running behind untrusted clients to
	// prevent request ID spoofing.
	TrustProxy *bool
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
	return cfg
}

func (cfg Config) validate() {}

var defaultGenerator = newBufferedGenerator()
