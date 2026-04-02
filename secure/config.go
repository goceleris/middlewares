package secure

import (
	"strconv"

	"github.com/goceleris/celeris"
)

// Config defines the security headers middleware configuration.
type Config struct {
	// Skip defines a function to skip this middleware for certain requests.
	Skip func(c *celeris.Context) bool

	// SkipPaths lists paths to skip (exact match).
	SkipPaths []string

	// XContentTypeOptions sets the X-Content-Type-Options header.
	// Default: "nosniff".
	XContentTypeOptions string

	// XFrameOptions sets the X-Frame-Options header.
	// Default: "SAMEORIGIN".
	XFrameOptions string

	// XSSProtection sets the X-XSS-Protection header.
	// Default: "0" (disables the XSS auditor, per modern best practice).
	XSSProtection string

	// HSTSMaxAge sets the max-age directive of Strict-Transport-Security in seconds.
	// Set to -1 to omit the header entirely. Default: 63072000 (2 years).
	HSTSMaxAge int

	// HSTSExcludeSubdomains opts out of includeSubDomains in the HSTS header.
	// By default includeSubDomains is included. Set to true to remove it.
	HSTSExcludeSubdomains bool

	// HSTSPreload adds preload to the HSTS header.
	// Default: false.
	HSTSPreload bool

	// ContentSecurityPolicy sets the Content-Security-Policy header.
	// Default: "" (omitted).
	ContentSecurityPolicy string

	// CSPReportOnly uses Content-Security-Policy-Report-Only instead of
	// Content-Security-Policy when true. Default: false.
	CSPReportOnly bool

	// ReferrerPolicy sets the Referrer-Policy header.
	// Default: "strict-origin-when-cross-origin".
	ReferrerPolicy string

	// PermissionsPolicy sets the Permissions-Policy header.
	// Default: "" (omitted).
	PermissionsPolicy string

	// CrossOriginOpenerPolicy sets the Cross-Origin-Opener-Policy header.
	// Default: "same-origin".
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy sets the Cross-Origin-Resource-Policy header.
	// Default: "same-origin".
	CrossOriginResourcePolicy string

	// CrossOriginEmbedderPolicy sets the Cross-Origin-Embedder-Policy header.
	// Default: "require-corp".
	CrossOriginEmbedderPolicy string

	// XDNSPrefetchControl sets the X-DNS-Prefetch-Control header.
	// Default: "off".
	XDNSPrefetchControl string

	// XPermittedCrossDomain sets the X-Permitted-Cross-Domain-Policies header.
	// Default: "none".
	XPermittedCrossDomain string

	// OriginAgentCluster sets the Origin-Agent-Cluster header.
	// Default: "?1".
	OriginAgentCluster string

	// XDownloadOptions sets the X-Download-Options header.
	// Default: "noopen".
	XDownloadOptions string
}

// DefaultConfig is the default security headers configuration.
var DefaultConfig = Config{
	XContentTypeOptions:       "nosniff",
	XFrameOptions:             "SAMEORIGIN",
	XSSProtection:             "0",
	HSTSMaxAge:                63072000,
	ReferrerPolicy:            "strict-origin-when-cross-origin",
	CrossOriginOpenerPolicy:   "same-origin",
	CrossOriginResourcePolicy: "same-origin",
	CrossOriginEmbedderPolicy: "require-corp",
	XDNSPrefetchControl:       "off",
	XPermittedCrossDomain:     "none",
	OriginAgentCluster:        "?1",
	XDownloadOptions:          "noopen",
}

func applyDefaults(cfg Config) Config {
	if cfg.XContentTypeOptions == "" {
		cfg.XContentTypeOptions = DefaultConfig.XContentTypeOptions
	}
	if cfg.XFrameOptions == "" {
		cfg.XFrameOptions = DefaultConfig.XFrameOptions
	}
	if cfg.XSSProtection == "" {
		cfg.XSSProtection = DefaultConfig.XSSProtection
	}
	if cfg.HSTSMaxAge == 0 {
		cfg.HSTSMaxAge = DefaultConfig.HSTSMaxAge
	}
	if cfg.ReferrerPolicy == "" {
		cfg.ReferrerPolicy = DefaultConfig.ReferrerPolicy
	}
	if cfg.CrossOriginOpenerPolicy == "" {
		cfg.CrossOriginOpenerPolicy = DefaultConfig.CrossOriginOpenerPolicy
	}
	if cfg.CrossOriginResourcePolicy == "" {
		cfg.CrossOriginResourcePolicy = DefaultConfig.CrossOriginResourcePolicy
	}
	if cfg.CrossOriginEmbedderPolicy == "" {
		cfg.CrossOriginEmbedderPolicy = DefaultConfig.CrossOriginEmbedderPolicy
	}
	if cfg.XDNSPrefetchControl == "" {
		cfg.XDNSPrefetchControl = DefaultConfig.XDNSPrefetchControl
	}
	if cfg.XPermittedCrossDomain == "" {
		cfg.XPermittedCrossDomain = DefaultConfig.XPermittedCrossDomain
	}
	if cfg.OriginAgentCluster == "" {
		cfg.OriginAgentCluster = DefaultConfig.OriginAgentCluster
	}
	if cfg.XDownloadOptions == "" {
		cfg.XDownloadOptions = DefaultConfig.XDownloadOptions
	}
	return cfg
}

func shouldEmit(v string) bool {
	return v != "" && v != Suppress
}

// Suppress is a sentinel value that, when set on a header field in [Config],
// causes that header to be omitted from the response entirely. Unlike an
// empty string (which is overridden by the default), Suppress explicitly
// opts out of a header after defaults have been applied.
const Suppress = "-"

func (cfg Config) validate() {
	if cfg.HSTSPreload && cfg.HSTSMaxAge > 0 && cfg.HSTSMaxAge < 31536000 {
		panic("secure: HSTSPreload requires HSTSMaxAge >= 31536000 (1 year)")
	}
	if cfg.HSTSPreload && cfg.HSTSExcludeSubdomains {
		panic("secure: HSTSPreload requires includeSubDomains (HSTSExcludeSubdomains must be false)")
	}
	if cfg.CSPReportOnly && cfg.ContentSecurityPolicy == "" {
		panic("secure: CSPReportOnly requires a non-empty ContentSecurityPolicy")
	}
}

// buildHeaders pre-computes the header key-value pairs from the config.
// Empty string values are excluded. HSTS is excluded here because it
// requires a runtime HTTPS check; see secure.go.
func buildHeaders(cfg Config) [][2]string {
	headers := make([][2]string, 0, 14)

	if shouldEmit(cfg.XContentTypeOptions) {
		headers = append(headers, [2]string{"x-content-type-options", cfg.XContentTypeOptions})
	}
	if shouldEmit(cfg.XFrameOptions) {
		headers = append(headers, [2]string{"x-frame-options", cfg.XFrameOptions})
	}
	if shouldEmit(cfg.XSSProtection) {
		headers = append(headers, [2]string{"x-xss-protection", cfg.XSSProtection})
	}
	if shouldEmit(cfg.ContentSecurityPolicy) {
		key := "content-security-policy"
		if cfg.CSPReportOnly {
			key = "content-security-policy-report-only"
		}
		headers = append(headers, [2]string{key, cfg.ContentSecurityPolicy})
	}
	if shouldEmit(cfg.ReferrerPolicy) {
		headers = append(headers, [2]string{"referrer-policy", cfg.ReferrerPolicy})
	}
	if shouldEmit(cfg.PermissionsPolicy) {
		headers = append(headers, [2]string{"permissions-policy", cfg.PermissionsPolicy})
	}
	if shouldEmit(cfg.CrossOriginOpenerPolicy) {
		headers = append(headers, [2]string{"cross-origin-opener-policy", cfg.CrossOriginOpenerPolicy})
	}
	if shouldEmit(cfg.CrossOriginResourcePolicy) {
		headers = append(headers, [2]string{"cross-origin-resource-policy", cfg.CrossOriginResourcePolicy})
	}
	if shouldEmit(cfg.CrossOriginEmbedderPolicy) {
		headers = append(headers, [2]string{"cross-origin-embedder-policy", cfg.CrossOriginEmbedderPolicy})
	}
	if shouldEmit(cfg.XDNSPrefetchControl) {
		headers = append(headers, [2]string{"x-dns-prefetch-control", cfg.XDNSPrefetchControl})
	}
	if shouldEmit(cfg.XPermittedCrossDomain) {
		headers = append(headers, [2]string{"x-permitted-cross-domain-policies", cfg.XPermittedCrossDomain})
	}
	if shouldEmit(cfg.OriginAgentCluster) {
		headers = append(headers, [2]string{"origin-agent-cluster", cfg.OriginAgentCluster})
	}
	if shouldEmit(cfg.XDownloadOptions) {
		headers = append(headers, [2]string{"x-download-options", cfg.XDownloadOptions})
	}

	return headers
}

// buildHSTSValue pre-computes the HSTS header value. Returns empty string
// when HSTS is disabled (HSTSMaxAge <= 0).
func buildHSTSValue(cfg Config) string {
	if cfg.HSTSMaxAge <= 0 {
		return ""
	}
	v := "max-age=" + strconv.Itoa(cfg.HSTSMaxAge)
	if !cfg.HSTSExcludeSubdomains {
		v += "; includeSubDomains"
	}
	if cfg.HSTSPreload {
		v += "; preload"
	}
	return v
}
